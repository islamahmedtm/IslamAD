using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace ADManagementWeb.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        public IActionResult Index()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> ExecuteADCommand(string command)
        {
            try
            {
                using (var runspace = RunspaceFactory.CreateRunspace())
                {
                    runspace.Open();

                    using (var powerShell = PowerShell.Create())
                    {
                        powerShell.Runspace = runspace;
                        
                        // Import AD module
                        powerShell.AddCommand("Import-Module").AddArgument("ActiveDirectory");
                        await powerShell.InvokeAsync();
                        powerShell.Commands.Clear();

                        // Execute the actual command
                        powerShell.AddScript(command);
                        var results = await powerShell.InvokeAsync();

                        return Json(new { success = true, data = results.Select(r => r.ToString()) });
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error executing AD command");
                return Json(new { success = false, error = ex.Message });
            }
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
} 