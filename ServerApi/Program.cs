using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using Polly;
using ServerApi;
using static OpenIddict.Abstractions.OpenIddictConstants;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews();
builder.Services.AddRazorPages();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// DB
builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection"));
    options.UseOpenIddict<Guid>();
});

// Identity
builder.Services.AddIdentity<ApplicationUser, IdentityRole<Guid>>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

builder.Services.AddAuthentication(IdentityConstants.ApplicationScheme);


// OpenIddict
builder.Services.AddOpenIddict()
    .AddCore(opt => opt.UseEntityFrameworkCore()
                   .UseDbContext<ApplicationDbContext>()
                   .ReplaceDefaultEntities<Guid>())
    .AddServer(opt =>
    {
        opt.SetAuthorizationEndpointUris("/connect/authorize");
        opt.SetTokenEndpointUris("/connect/token");
        opt.SetEndSessionEndpointUris("/connect/logout");
        opt.SetRevocationEndpointUris("/connect/revocation");

        opt.AllowAuthorizationCodeFlow()
            .RequireProofKeyForCodeExchange()
            .AllowRefreshTokenFlow(); // ← PKCE

        opt.AcceptAnonymousClients(); // ← No client secret

        opt.AddDevelopmentEncryptionCertificate();
        opt.AddDevelopmentSigningCertificate();

        opt.RegisterScopes(
            Scopes.OpenId,
            Scopes.Profile,
            Scopes.Email,
            Scopes.OfflineAccess,
            Scopes.Roles);

        opt.UseAspNetCore()
            .EnableAuthorizationEndpointPassthrough()
            .EnableTokenEndpointPassthrough()
            .EnableEndSessionEndpointPassthrough()
            .EnableStatusCodePagesIntegration();

        // Temp
        opt.SetAccessTokenLifetime(TimeSpan.FromMinutes(1));
        opt.SetRefreshTokenLifetime(TimeSpan.FromDays(1));
    })
    .AddValidation(opt =>
    {
        opt.UseLocalServer();
        opt.UseAspNetCore();
        opt.AddAudiences("resource_server");
    });

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseStaticFiles();
app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");
app.MapRazorPages();

await SeedDataAsync(app.Services);

app.Run();

// Seed default client
static async Task SeedDataAsync(IServiceProvider services)
{
    using var scope = services.CreateScope();

    // Get Services
    var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole<Guid>>>();
    var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

    await context.Database.MigrateAsync(); // Migrate DB

    // Create role(s)
    var roles = new List<string>() { "User" };
    foreach (var role in roles)
    {
        if (!await roleManager.RoleExistsAsync(role))
        {
            await roleManager.CreateAsync(new IdentityRole<Guid>(role));
        }
    }

    // Create User
    var user = new ApplicationUser()
    {
        Email = "test@test.dk",
        EmailConfirmed = true,
        UserName = "test@test.dk",
        PhoneNumberConfirmed = true,
    };

    if (await userManager.FindByEmailAsync("test@test.dk") == null)
    {
        var result = await userManager.CreateAsync(user, "Test1234!");
        if (result.Succeeded)
        {
            if (!await userManager.IsInRoleAsync(user, roles[0]))
            {
                await userManager.AddToRoleAsync(user, roles[0]);
            }
        }
    }

    // Create OpenId Application
    if (await manager.FindByClientIdAsync("web-client") is null)
    {
        await manager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = "web-client",
            ConsentType = ConsentTypes.Explicit,
            DisplayName = "Web Client App",
            RedirectUris = { new Uri("https://localhost:7070/signin-oidc") },
            PostLogoutRedirectUris = { new Uri("https://localhost:7070/signout-callback-oidc") },
            Permissions =
            {
                Permissions.Endpoints.Authorization,
                Permissions.Endpoints.Token,
                Permissions.Endpoints.EndSession,
                Permissions.Endpoints.Revocation,

                Permissions.GrantTypes.AuthorizationCode,
                Permissions.GrantTypes.RefreshToken,

                Permissions.ResponseTypes.Code,

                Permissions.Scopes.Email,
                Permissions.Scopes.Profile,
                Permissions.Scopes.Roles,
                Permissions.Prefixes.Scope + Scopes.OpenId,
                Permissions.Prefixes.Scope + Scopes.OfflineAccess,
            },
            Requirements =
            {
                Requirements.Features.ProofKeyForCodeExchange
            }
        });
    }
}