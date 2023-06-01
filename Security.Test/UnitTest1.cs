using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Moq;
using Security.Controllers;

namespace security.test;

[TestFixture]

public class Tests
{
    List<LoginModel> list;
    private ILogger<AuthenticationController>? logger;
    private IConfiguration? config;

    [SetUp]
    public void Setup()
    {
        logger = Mock.Of<ILogger<AuthenticationController>>();
        config = Mock.Of<IConfiguration>();
        list = new List<LoginModel>();
        list.Add(new LoginModel("user@user.com", "password1"));
    }

    [Test]
    public void invalidLoginEmail()
    {
        try
        {
            AuthenticationController auth = new AuthenticationController(logger, config);
            LoginModel loginmodel = new LoginModel(null, "password1");
            auth.Login(loginmodel);
            
        }
        catch (Exception ex)
        {
            Assert.AreEqual("Value cannot be null. (Parameter 'email')", ex.Message);
        }
    }

    [Test]
  public void invalidLoginPassword()
    {
        try
        {
            AuthenticationController auth = new AuthenticationController(logger, config);
            LoginModel loginmodel = new LoginModel("user1", null);
            auth.Login(loginmodel);
            
        }
        catch (Exception ex)
        {
            Assert.AreEqual("Value cannot be null. (Parameter 'password')", ex.Message);
        }
    }

    [Test]
    public void invalidLogin()
    {
        try
        {
            AuthenticationController auth = new AuthenticationController(logger, config);
            LoginModel loginmodel = new LoginModel(null, null);
            auth.Login(loginmodel);
            
        }
        catch (Exception ex)
        {
            Assert.AreEqual("Value cannot be null. (Parameter 'email', Parameter 'password')", ex.Message);
        }
    }

    [Test]
    public void validLogin()
    {
        AuthenticationController auth = new AuthenticationController(logger, config);
        LoginModel loginmodel = new LoginModel("newuser@user.com", "password2");
        list.Add(loginmodel);
        auth.Login(loginmodel);

        Assert.IsTrue(list.Count == 2);
        Assert.AreEqual(list[1], loginmodel);
        Assert.IsTrue(list[1].Email == loginmodel.Email); 
        Assert.IsTrue(list[1].Password == loginmodel.Password);
    }
    
}