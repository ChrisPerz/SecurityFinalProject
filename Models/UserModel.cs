namespace SecurityFinalProject.Models;
using System.ComponentModel.DataAnnotations;

public class UserModel
{
    [Required]
    [StringLength(50)]
    [RegularExpression(@"^[a-zA-Z0-9_]+$", ErrorMessage = "Username can only contain letters, numbers, and underscores.")]
    public string Username { get; set; }

    [Required, EmailAddress]
    public string Email { get; set; }

    [Required]
    [StringLength(100, MinimumLength = 6)]
    [DataType(DataType.Password)]
    public string Password { get; set; }

    public string HashedPassword { get; set; }
    public int UserId { get; set; }
}