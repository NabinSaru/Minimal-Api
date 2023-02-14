namespace Identity_Management.Models
{
    /// <summary>
    /// User clas to hold the define the user and their privelege
    /// </summary>
    public class User
    {
        public string Username { get; set; }
        public string PasswordHash { get; set; }
        // initiate the empty list for claims as it can't be nil
        public List<UserClaim> Claims { get; set; } = new();
    }
}
