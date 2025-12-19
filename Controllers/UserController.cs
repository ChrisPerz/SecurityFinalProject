using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NUnit.Framework;
using Org.BouncyCastle.Asn1.Cms;
using SecurityFinalProject.Models;

public class UserController : Controller
{
    private  DatabaseService _databaseService;
    private readonly TokenService _tokenService;
    private readonly PasswordService _passwordService;
    public UserController(DatabaseService databaseService, TokenService tokenService, PasswordService passwordService)
    {
        _databaseService = databaseService;
        _tokenService = tokenService;
        _passwordService = passwordService;
    }
    // GET: UserForm/Create
    public ActionResult Create()
    {
        return View();
    }

    // POST: UserForm/Create
    [HttpPost]
    [Authorize(Policy = "AdminOnly")]
    public ActionResult Create(UserModel model)
    {
        if (!IsValidInput(model.Username, "username") || !IsValidInput(model.Email, "email"))
        {
            ModelState.AddModelError("", "Input contains unsafe characters.");
        }
        // data annotations and model validation allow the correct input, it helps with xss too.
        if (ModelState.IsValid)
        {
            model.Username = SanitizeForXss(model.Username).Trim();
            model.Email = SanitizeForXss(model.Email).Trim();
            model.HashedPassword = _passwordService.HashPassword(model.Password);
            try
            {
                // Store the hashed password in the database instead of plaintext
                _databaseService.CreateUser(model.Username, model.Email, model.HashedPassword);
                ViewBag.Message = "User created successfully!";
                return View(model);
                // return RedirectToAction("Create");
            }
            catch (Exception ex)
            {
                ModelState.AddModelError("", "Database error: " + ex.Message);
                return View(model);
            }
        }
        return View(model);
    }

    [HttpPost("login")]
     [Authorize]
    public async Task<ActionResult> Login(string email, string password)
    {
        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
            return BadRequest("Email and password are required.");

        var user = await _databaseService.GetUserByEmailAsync(email);


        if (user == null)
            return Unauthorized("Invalid credentials.");

    
        bool isValid = _passwordService.VerifyPassword(password, user.HashedPassword);

        if (!isValid)
            return Unauthorized("Invalid credentials.");

        // Generate token with additional claims
        var token = _tokenService.GenerateTokenWithClaim(user.UserId.ToString());
        return Ok(new { Token = token });
    }
  public static bool IsValidInput(string input, string fieldType)
    {
        if (string.IsNullOrWhiteSpace(input)) return false;

        // Validate based on field type
        switch (fieldType.ToLower())
        {
            case "username":
                // check for alphanumeric and underscores, length 3-50 
                return Regex.IsMatch(input, @"^[a-zA-Z0-9_]{3,50}$");

            case "email":
                // basic email pattern
                return Regex.IsMatch(input, @"^[^@\s]+@[^@\s]+\.[^@\s]+$");

            default:
                // Unknown field type
                return !Regex.IsMatch(input, "<.*?>");
        }
    }


    public static string SanitizeForXss(string input)
    {
        if (string.IsNullOrEmpty(input)) return string.Empty;

        // Escapar caracteres peligrosos
        return input
            .Replace("&", "&amp;")
            .Replace("<", "&lt;")
            .Replace(">", "&gt;")
            .Replace("\"", "&quot;")
            .Replace("'", "&#x27;");
    }

}
