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
[Route("api/[controller]")]
public class AuthenticationController : ControllerBase
{
    private readonly IConfiguration _config;
    private readonly ILogger<AuthenticationController> _logger;
    private readonly IServiceCollection _services;
    protected static IMongoClient _client;
    protected static IMongoDatabase _db;
    private static string? _connString;
    private static string? myIssuer;
    private static string? mySecret;


    // Vault deployment-issues
    /*
    private Vault vault;
    */

    public AuthenticationController(ILogger<AuthenticationController> logger, IConfiguration config)
    {
        _logger = logger;
        _config = config;
        _connString = config["MongoConnection"];
        myIssuer = config["Issuer"];
        mySecret = config["Secret"];

        // Vault deployment-issues
        /*
        vault = new Vault(_config);
        string cons = vault.GetSecret("dbconnection", "constring").Result;
        */

        _client = new MongoClient(_connString);
        _db = _client.GetDatabase("user");
    }
    const int keySize = 64;
    const int iterations = 350000;
    HashAlgorithmName hashAlgorithm = HashAlgorithmName.SHA512;

    //Varificerer passwordet ved at hashe det og sammenligne det med det hashede password i databasen
    bool VerifyPassword(string password, string hash, byte[] salt)
    {
        _logger.LogInformation("Attempting to verify password...");
        var hashToCompare = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, hashAlgorithm, keySize);
        return hashToCompare.SequenceEqual(Convert.FromHexString(hash));
    }

    //Genererer en JWT token udfra email og en user rolle
    private string GenerateJwtToken(string email, string role)
    {
        _logger.LogInformation($"Attempting to generate JWT-token for {email}");

        // Vault deployment-issues
        /*
        vault = new Vault(_config);
        */

        // henter secret og issuer fra vault
        _logger.LogInformation("Fetching Secret and issuer...");

        // Vault deployment-issues
        /*
        string mySecret = vault.GetSecret("authentication", "secret").Result;
        string myIssuer = vault.GetSecret("authentication", "issuer").Result;
        */

        //laver security key, credentials og claims
        _logger.LogInformation("Constructing claims and credentials...");
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(mySecret));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, email),
            new Claim(ClaimTypes.Role, role)
        };

        //Genererer token udfra issuer, claims og credentials variablerne
        _logger.LogInformation("Generating token...");
        var token = new JwtSecurityToken(
            myIssuer,
            "http://localhost",
            claims,
            expires: DateTime.Now.AddMinutes(15),
            signingCredentials: credentials);

        _logger.LogInformation($"Successfully generated a token for {email} with the role {role}.");
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    //retunerer en user token
    [AllowAnonymous]
    [HttpPost("login")]
    public async Task<IActionResult> Login(LoginModel loginModel)
    {
        //henter collection fra databasen og finder en bruger efter email
        _logger.LogInformation("Attempting to login user...");
        var collection = _db.GetCollection<LoginModel>("users");

        _logger.LogInformation($"Checking if user with email {loginModel.Email} exists...");
        var user = await collection.Find(u => u.Email == loginModel.Email).FirstOrDefaultAsync();
        //hvis brugeren ikke findes returneres en 401
        if (user == null)
        {
            _logger.LogError($"Did not find user with the email {loginModel.Email}");
            return Unauthorized();
        }
        //hvis passwordet ikke matcher returneres en 401
        if (VerifyPassword(loginModel.Password, user.Password, user.PasswordSalt) == false)
        {
            _logger.LogError($"Password verification failed for user {loginModel.Email}");
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
        _logger.LogInformation("Attempting to login admin...");
        var collection = _db.GetCollection<LoginModel>("admin");

        _logger.LogInformation($"Checking if admin with email {loginModel.Email} exists...");
        var user = await collection.Find(u => u.Email == loginModel.Email).FirstOrDefaultAsync();
        //hvis admin brugeren ikke findes returneres en 401
        if (user == null)
        {
            _logger.LogError($"Did not find admin with the email {loginModel.Email}");
            return Unauthorized();
        }
        //hvis passwordet ikke matcher returneres en 401
        if (VerifyPassword(loginModel.Password, user.Password, user.Salt) == false)
        {
            _logger.LogError($"Password verification failed for user {loginModel.Email}");
            return Unauthorized();
        }
        //hvis admin brugeren findes og passwordet matcher, genereres en token og returneres
        var token = GenerateJwtToken(user.Email, user.Role);
        return Ok(new { token });
    }
}
