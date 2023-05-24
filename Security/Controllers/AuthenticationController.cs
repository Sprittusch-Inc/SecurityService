using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Security.Models;
using MongoDB.Driver;
using Microsoft.Extensions.Configuration;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;

namespace Security.Controllers;

[ApiController]
[Route("[controller]")]
public class AuthenticationController : ControllerBase
{
    private readonly IConfiguration _config;
    private readonly ILogger<AuthenticationController> _logger;
    private readonly IServiceCollection _services;
    protected static IMongoClient _client;
    protected static IMongoDatabase _db;
    private Vault vault = new();

    public AuthenticationController(ILogger<AuthenticationController> logger, IConfiguration config)
    {
        string cons = vault.GetSecret("dbconnection", "constring").Result;
        _logger = logger;
        _config = config;
        _client = new MongoClient(cons);
        _db = _client.GetDatabase("user");
    }
    const int keySize = 64;
    const int iterations = 350000;
    HashAlgorithmName hashAlgorithm = HashAlgorithmName.SHA512;

    bool VerifyPassword(string password, string hash, byte[] salt)
    {
        var hashToCompare = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, hashAlgorithm, keySize);
        return hashToCompare.SequenceEqual(Convert.FromHexString(hash));
    }

    private string GenerateJwtToken(string email, string role)
    {
        string mySecret = vault.GetSecret("authentication", "secret").Result;
        string myIssuer = vault.GetSecret("authentication", "issuer").Result;
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(mySecret));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, email),
            new Claim(ClaimTypes.Role, role)
        };
        var token = new JwtSecurityToken(
            myIssuer,
            "http://localhost",
            claims,
            expires: DateTime.Now.AddMinutes(15),
            signingCredentials: credentials);
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    [AllowAnonymous]
    [HttpPost("login")]
    public async Task<IActionResult> Login(LoginModel loginModel)
    {
        var collection = _db.GetCollection<LoginModel>("users");
        var user = await collection.Find(u => u.Email == loginModel.Email).FirstOrDefaultAsync();
        if (user == null)
        {
            return Unauthorized();
        }
        if (VerifyPassword(loginModel.Password, user.Password, user.PasswordSalt) == false)
        {
            return Unauthorized();
        }
        var token = GenerateJwtToken(user.Email, user.Role);
        return Ok(new { token });
    }

    [AllowAnonymous]
    [HttpPost("adminlogin")]
    public async Task<IActionResult> AdminLogin(LoginModel loginModel)
    {
        var collection = _db.GetCollection<LoginModel>("admin");
        var user = await collection.Find(u => u.Email == loginModel.Email).FirstOrDefaultAsync();
        if (user == null)
        {
            return Unauthorized();
        }
        if (VerifyPassword(loginModel.Password, user.Password, user.Salt) == false)
        {
            return Unauthorized();
        }
        var token = GenerateJwtToken(user.Email, user.Role);
        return Ok(new { token });
    }

    [AllowAnonymous]
    [HttpPost("validate")]
    public async Task<IActionResult> ValidateToken([FromBody] string? token)
    {
        if (token == null)
        {
            return BadRequest("Token is invalid");
        }

        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(vault.GetSecret("authentication", "secret").Result);

        try
        {
            tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidIssuer = vault.GetSecret("authentication", "issuer").Result
            }, out SecurityToken validatedToken);

            var jwtToken = (JwtSecurityToken)validatedToken;
            var email = jwtToken.Claims.First(x => x.Type == ClaimTypes.NameIdentifier).Value;

            return Ok(email);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex.Message);
            return StatusCode(404);
        }
    }

}
