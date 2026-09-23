using System.ComponentModel.DataAnnotations;

namespace JWTAuth.Models;

public sealed class SessionActionInput
{
    [Required]
    public string CsrfToken { get; init; } = string.Empty;
}
