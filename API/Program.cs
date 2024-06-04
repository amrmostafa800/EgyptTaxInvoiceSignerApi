
using API.Dto;
using API.Signature;
using Microsoft.AspNetCore.Mvc;

namespace API
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            builder.Services.AddAuthorization();

            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();

            builder.Services.AddSingleton<SignatureService>();

            builder.WebHost.ConfigureKestrel(serverOptions =>
            {
                serverOptions.ListenAnyIP(5226); // HTTP
                serverOptions.ListenAnyIP(7209, listenOptions =>
                {
                    listenOptions.UseHttps(); // HTTPS
                });
            });

            var app = builder.Build();

            //// Configure the HTTP request pipeline.
            //if (app.Environment.IsDevelopment())
            //{
            app.UseSwagger();
            app.UseSwaggerUI();
            //}

            app.UseHttpsRedirection();

            app.UseAuthorization();

            app.MapPost("/sign", ([FromBody] SignRequestDto signRequest) =>
            {
                var signatureService = app.Services.GetRequiredService<SignatureService>();

                return signatureService.SignInvoice(signRequest);
            })
            .WithName("SignInvoice")
            .WithOpenApi();

            app.Run();
        }
    }
}
