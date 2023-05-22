namespace security.test;

[TestFixture]

public class Tests
{
    List<User> list;

    [SetUp]
    public void Setup()
    {
        list = new List<LoginModel>();
        list.Add(new LoginModel("user@user.com", "password1"));
    }

    [Test]
    public void invalidLoginEmail()
    {
        LoginModel loginmodel = new LoginModel(null, "password1");
        Assert.IsFalse(Login(loginmodel));
    }

    [Test]
    public void invalidLoginPassword()
    {
        LoginModel loginmodel = new LoginModel("user@user.com", null);
        Assert.IsFalse(Login(loginmodel));
    }

    [Test]
    public void invalidLogin()
    {
        LoginModel loginmodel = new LoginModel(null, null);
        Assert.IsFalse(Login(loginmodel));
    }

    [Test]
    public void validLogin()
    {
        LoginModel loginmodel = new LoginModel("user@user.com", "password1");
        Assert.IsTrue(Login(loginmodel));
    }
}