
using SecurityFinalProject.Models;
using MySql.Data.MySqlClient;

public class DatabaseService
{
    public UserModel GetUser(string username, string email)
    {
        string query = "SELECT UserID, Username, Email FROM Users WHERE Username = @Username AND Email = @Email";

        using (MySqlConnection conn = new MySqlConnection("Server=localhost;Database=YourDB;User ID=yourUser;Password=yourPass;"))
        using (MySqlCommand cmd = new MySqlCommand(query, conn))
        {
            // Add parameters safely
            cmd.Parameters.Add("@Username", MySqlDbType.VarChar).Value = username;
            cmd.Parameters.Add("@Email", MySqlDbType.VarChar).Value = email;

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

    public void CreateUser(string username, string email)
    {
        string query = "INSERT INTO Users (Username, Email) VALUES (@Username, @Email)";

        using (MySqlConnection conn = new MySqlConnection("Server=localhost;Database=YourDB;User ID=yourUser;Password=yourPass;"))
        using (MySqlCommand cmd = new MySqlCommand(query, conn))
        {
            // Add parameters safely
            cmd.Parameters.Add("@Username", MySqlDbType.VarChar).Value = username;
            cmd.Parameters.Add("@Email", MySqlDbType.VarChar).Value = email;

            conn.Open();
            cmd.ExecuteNonQuery();
        }
    }

}