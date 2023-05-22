namespace Security.Models
{
    public class User
    {
        public string Username { get; set; }
        public string Password { get; set; }


        public User(string username, string password)
        {
            if (username == null)
            {
                throw new Exception("Username cannot be null");
            }
            if (password == null)
            {
                throw new Exception("Password cannot be null");
            }

            this.Username = username;
            this.Password = password;
        }

        public bool Login(User user)
        {
            if (user.Username == null)
            {
                throw new Exception("Username cannot be null");
                return false;
            }
            else if (user.Password == null)
            {
                throw new Exception("Password cannot be null");
                return false;
            } else 
            {
                return true;
            }
            
        }
    }
}