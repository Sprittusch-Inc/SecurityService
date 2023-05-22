namespace security.test;

[TestFixture]
public class Tests
{
    private List<User>? list;

    [SetUp]
    public void Setup()
    {
        
        list = new List<User>();
        list.Add(new User("user1", "password1"));
    }

    [TestCase(null, "password1")]
    [TestCase("user1", null)]
    [TestCase(null, null)]

    public void Login(string username, string password)
    {
        Assert.Throws<Exception>(() =>
        {
            User user = new User(username, password);
        });
    }

    [Test]
    public void Login()
    {
        User user = new User("user1", "password1");
        Assert.IsTrue(user.Login(user));
    }
}