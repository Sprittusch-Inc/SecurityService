using Security.Controllers;

namespace security.test;

[TestFixture]

public class Tests
{
    List<LoginModel> list;

    [SetUp]
    public void Setup()
    {
        list = new List<LoginModel>();
        list.Add(new LoginModel("user@user.com", "password1"));
    }

    [Test]
    public static void invalidLoginEmail()
    {
        AuthenticationController auth = new AuthenticationController();
        LoginModel loginmodel = new LoginModel(null, "password1");
        Assert.IsFalse(auth.Login(loginmodel));
    }

    [Test]
    public void invalidLoginPassword()
    {
        AuthenticationController auth = new AuthenticationController();
        LoginModel loginmodel = new LoginModel("user@user.com", null);
        Assert.IsFalse(auth.Login(loginmodel));
    }

    [Test]
    public void invalidLogin()
    {
        AuthenticationController auth = new AuthenticationController();
        LoginModel loginmodel = new LoginModel(null, null);
        Assert.IsFalse(auth.Login(loginmodel));
    }

    [Test]
    public void validLogin()
    {
        AuthenticationController auth = new AuthenticationController();
        LoginModel loginmodel = new LoginModel("user@user.com", "password1");
        Assert.IsTrue(auth.Login(loginmodel));
    }
}