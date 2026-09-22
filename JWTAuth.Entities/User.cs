namespace JWTAuth.Entities
{
    public class User
    {
        public long UserId { get; set; }
        public required string Username { get; set; }
        public required string NormalizedUsername { get; set; }
        public required string PasswordHash { get; set; }
    }
}
