namespace Identity_Management.Models
{
    /// <summary>
    /// User claim to store the claim principal
    /// </summary>
    public class UserClaim
    {
        public string Type { get; set; }
        public string Value { get; set; }
    }
}
