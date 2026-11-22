using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Winche.Auth.Data.Migrations
{
    /// <inheritdoc />
    public partial class UserPhotos : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "PhotoSource",
                table: "auth_users",
                type: "character varying(80)",
                maxLength: 80,
                nullable: true);

            migrationBuilder.CreateTable(
                name: "auth_user_photos",
                columns: table => new
                {
                    UserId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    PhotoId = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false),
                    ContentType = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    Bytes = table.Column<byte[]>(type: "bytea", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_auth_user_photos", x => x.UserId);
                    table.ForeignKey(
                        name: "FK_auth_user_photos_auth_users_UserId",
                        column: x => x.UserId,
                        principalTable: "auth_users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "auth_user_photos_photo",
                table: "auth_user_photos",
                column: "PhotoId",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "auth_user_photos");

            migrationBuilder.DropColumn(
                name: "PhotoSource",
                table: "auth_users");
        }
    }
}
