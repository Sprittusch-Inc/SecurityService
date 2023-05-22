using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Security.Models;
using MongoDB.Driver;

namespace Security.Controllers;

[ApiController]
[Route("[controller]")]
public class AuthenticationController : ControllerBase
{
    private readonly IConfiguration _config;
    private readonly ILogger<AuthenticationController> _logger;
    protected static IMongoClient _client;
    protected static IMongoDatabase _db;
    private Vault vault = new();
    private Hashing hashing = new();

    public AuthenticationController(ILogger<AuthenticationController> logger, Iconfiguration config)
    {
        string cons = vault.GetSecret("dbconnection", "constring").Result;
        _logger = logger;
        _config = config;
        _client = new MongoClient(cons);
        _db = _client.GetDatabase("user");
    }

    bool VerifyPassword(string password, string hash, byte[] salt)
    {
        var hashToCompare = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, hashAlgorithm, keySize);
        return hashToCompare.SequenceEqual(Convert.FromHexString(hash));
    }

    private string GenerateJwtToken(string username)
    {
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Secret"]));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, username)
        };
        var token = new JwtSecurityToken(
            _config["Issuer"],
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
        var collection = _db.GetCollection<User>("users");
        var user = await collection.Find(u => u.Email == loginModel.Email).FirstOrDefaultAsync();
        if (user == null)
        {
            return Unauthorized();
        }
        if (VerifyPassword(login.Password, result.Password, result.Salt) == false)
        {
            return Unauthorized();
        }
        var token = GenerateJwtToken(user.Email);
        return Ok(new { token });
    }

}