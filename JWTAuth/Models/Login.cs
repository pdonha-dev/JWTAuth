using System.ComponentModel.DataAnnotations;

namespace JWTAuth.Models;

public sealed class Login
{
    [Required(ErrorMessage = "O nome de usuário é obrigatório")]
    [StringLength(64, MinimumLength = 3, ErrorMessage = "Usuário ou senha inválidos")]
    [RegularExpression("^[A-Za-z0-9._-]+$", ErrorMessage = "Usuário ou senha inválidos")]
    public string Username { get; init; } = string.Empty;

    [Required(ErrorMessage = "A senha é obrigatória")]
    public string Password { get; init; } = string.Empty;
}
