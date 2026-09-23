using System.ComponentModel.DataAnnotations;

namespace JWTAuth.Models;

public sealed class RegisterUser
{
    [Required(ErrorMessage = "O nome de usuário é obrigatório")]
    [StringLength(64, MinimumLength = 3, ErrorMessage = "O nome de usuário deve ter entre 3 e 64 caracteres")]
    [RegularExpression("^[A-Za-z0-9._-]+$", ErrorMessage = "Use apenas letras, números, ponto, hífen ou sublinhado")]
    public string Username { get; init; } = string.Empty;

    [Required(ErrorMessage = "A senha é obrigatória")]
    [MinLength(12, ErrorMessage = "A senha deve ter pelo menos 12 caracteres")]
    public string Password { get; init; } = string.Empty;
}
