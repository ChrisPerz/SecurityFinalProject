using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc;
using SecurityFinalProject.Models;

public class UserController : Controller
{
    private  DatabaseService _databaseService;
    public UserController(DatabaseService databaseService)
    {
        _databaseService = databaseService;
    }
    // GET: UserForm/Create
    public ActionResult Create()
    {
        return View();
    }

    // POST: UserForm/Create
    [HttpPost]
    public ActionResult Create(UserModel model)
    {
        if (!IsValidInput(model.Username, "user") || !IsValidInput(model.Email, "email"))
        {
            ModelState.AddModelError("", "Input contains unsafe characters.");
        }
        // data annotations and model validation allow the correct input, it helps with xss too.
        if (ModelState.IsValid)
        {
            model.Username = SanitizeForXss(model.Username).Trim();
            model.Email = SanitizeForXss(model.Email).Trim();
            try
            {
                _databaseService.CreateUser(model.Username, model.Email);
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
