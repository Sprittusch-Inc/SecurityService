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

    //Varificerer passwordet ved at hashe det og sammenligne det med det hashede password i databasen
    bool VerifyPassword(string password, string hash, byte[] salt)
    {
        var hashToCompare = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, hashAlgorithm, keySize);
        return hashToCompare.SequenceEqual(Convert.FromHexString(hash));
    }

    //Genererer en JWT token udfra email og en user rolle
    private string GenerateJwtToken(string email, string role)
    {
        //henter secret og issuer fra vault
        string mySecret = vault.GetSecret("authentication", "secret").Result;
        string myIssuer = vault.GetSecret("authentication", "issuer").Result;
        //laver security key, credentials og claims
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(mySecret));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, email),
            new Claim(ClaimTypes.Role, role)
        };
        //Genererer token udfra issuer, claims og credentials variablerne
        var token = new JwtSecurityToken(
            myIssuer,
            "http://localhost",
            claims,
            expires: DateTime.Now.AddMinutes(15),
            signingCredentials: credentials);
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    //retunerer en user token
    [AllowAnonymous]
    [HttpPost("login")]
    public async Task<IActionResult> Login(LoginModel loginModel)
    {
        //henter collection fra databasen og finder en bruger efter email
        var collection = _db.GetCollection<LoginModel>("users");
        var user = await collection.Find(u => u.Email == loginModel.Email).FirstOrDefaultAsync();
        //hvis brugeren ikke findes returneres en 401
        if (user == null)
        {
            return Unauthorized();
        }
        //hvis passwordet ikke matcher returneres en 401
        if (VerifyPassword(loginModel.Password, user.Password, user.PasswordSalt) == false)
        {
            return Unauthorized();
        }
        //hvis brugeren findes og passwordet matcher, genereres en token og returneres
        var token = GenerateJwtToken(user.Email, user.Role);
        return Ok(new { token });
    }


    //returner en admin token
    [AllowAnonymous]
    [HttpPost("adminlogin")]
    public async Task<IActionResult> AdminLogin(LoginModel loginModel)
    {
        //henter collection fra databasen og finder en admin bruger efter email
        var collection = _db.GetCollection<LoginModel>("admin");
        var user = await collection.Find(u => u.Email == loginModel.Email).FirstOrDefaultAsync();
        //hvis admin brugeren ikke findes returneres en 401
        if (user == null)
        {
            return Unauthorized();
        }
        //hvis passwordet ikke matcher returneres en 401
        if (VerifyPassword(loginModel.Password, user.Password, user.Salt) == false)
        {
            return Unauthorized();
        }
        //hvis admin brugeren findes og passwordet matcher, genereres en token og returneres
        var token = GenerateJwtToken(user.Email, user.Role);
        return Ok(new { token });
    }
}
