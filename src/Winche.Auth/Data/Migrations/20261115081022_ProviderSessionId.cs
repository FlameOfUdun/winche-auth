using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Winche.Auth.Data.Migrations
{
    /// <inheritdoc />
    public partial class ProviderSessionId : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "ProviderSessionId",
                table: "auth_sessions",
                type: "character varying(256)",
                maxLength: 256,
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "auth_sessions_provider_session",
                table: "auth_sessions",
                columns: new[] { "Provider", "ProviderSessionId" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "auth_sessions_provider_session",
                table: "auth_sessions");

            migrationBuilder.DropColumn(
                name: "ProviderSessionId",
                table: "auth_sessions");
        }
    }
}
