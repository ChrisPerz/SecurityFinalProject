using BCrypt.Net;

public class PasswordService
{
    public string HashPassword(string plainPassword)
    {
        // used BCrypt to hash the password with a work factor of 12 to enhance security
        return BCrypt.Net.BCrypt.HashPassword(plainPassword, workFactor: 12);
    }

    // verify password against hashed password
    public bool VerifyPassword(string plainPassword, string hashedPassword)
    {
        return BCrypt.Net.BCrypt.Verify(plainPassword, hashedPassword);
    }
}