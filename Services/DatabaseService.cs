
using SecurityFinalProject.Models;
using MySql.Data.MySqlClient;

public class DatabaseService
{
    public UserModel GetUser(string username, string password)
    {
        string query = "SELECT UserID, Username, Email FROM Users WHERE Username = @Username AND Password = @Password";

        using (MySqlConnection conn = new MySqlConnection("Server=localhost;Database=YourDB;User ID=yourUser;Password=yourPass;"))
        using (MySqlCommand cmd = new MySqlCommand(query, conn))
        {
            // Add parameters safely
            cmd.Parameters.Add("@Username", MySqlDbType.VarChar).Value = username;
            cmd.Parameters.Add("@Password", MySqlDbType.VarChar).Value = password;

            conn.Open();
            using (MySqlDataReader reader = cmd.ExecuteReader())
            {
                if (reader.Read())
                {
                    return new UserModel
                    {
                        Username = reader.GetString("Username"),
                        Email = reader.GetString("Email")
                    };
                }
            }
        }
        return null;
    }

    public async Task<UserModel?> GetUserByEmailAsync(string email)
    {
        const string query = "SELECT UserID, Username, Email, Password FROM Users WHERE Email = @Email";

        await using var conn = new MySqlConnection("Server=localhost;Database=YourDB;User ID=yourUser;Password=yourPass;");
        await using var cmd = new MySqlCommand(query, conn);
        cmd.Parameters.AddWithValue("@Email", email);

        await conn.OpenAsync();
        await using var reader = await cmd.ExecuteReaderAsync();

        if (await reader.ReadAsync())
        {
            return new UserModel
            {
                UserId = reader.GetInt32(reader.GetOrdinal("UserID")),
                Username = reader.GetString(reader.GetOrdinal("Username")),
                Email = reader.GetString(reader.GetOrdinal("Email")),
                HashedPassword = reader.GetString(reader.GetOrdinal("Password"))
            };
        }

        return null;
    }
    public void CreateUser(string username, string email, string password)
    {
        string query = "INSERT INTO Users (Username, Email, Password) VALUES (@Username, @Email, @Password)";

        using (MySqlConnection conn = new MySqlConnection("Server=localhost;Database=YourDB;User ID=yourUser;Password=yourPass;"))
        using (MySqlCommand cmd = new MySqlCommand(query, conn))
        {
            // Add parameters safely
            cmd.Parameters.Add("@Username", MySqlDbType.VarChar).Value = username;
            cmd.Parameters.Add("@Email", MySqlDbType.VarChar).Value = email;
            cmd.Parameters.Add("@Password", MySqlDbType.VarChar).Value = password;

            conn.Open();
            cmd.ExecuteNonQuery();
        }
    }

}