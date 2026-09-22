using JWTAuth.Db.Context;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Infrastructure;

#nullable disable

namespace JWTAuth.Db.Migrations;

[DbContext(typeof(DataContext))]
[Migration("20260320000000_AddNormalizedUsername")]
public partial class AddNormalizedUsername : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AlterColumn<string>(
            name: "Username",
            table: "User",
            type: "character varying(64)",
            maxLength: 64,
            nullable: false,
            oldClrType: typeof(string),
            oldType: "text");

        migrationBuilder.AlterColumn<string>(
            name: "Password",
            table: "User",
            type: "character varying(100)",
            maxLength: 100,
            nullable: false,
            oldClrType: typeof(string),
            oldType: "text");

        migrationBuilder.AddColumn<string>(
            name: "NormalizedUsername",
            table: "User",
            type: "character varying(64)",
            maxLength: 64,
            nullable: true);

        migrationBuilder.Sql("UPDATE \"User\" SET \"NormalizedUsername\" = UPPER(BTRIM(\"Username\"));");

        migrationBuilder.AlterColumn<string>(
            name: "NormalizedUsername",
            table: "User",
            type: "character varying(64)",
            maxLength: 64,
            nullable: false,
            oldClrType: typeof(string),
            oldType: "character varying(64)",
            oldMaxLength: 64,
            oldNullable: true);

        migrationBuilder.CreateIndex(
            name: "IX_User_NormalizedUsername",
            table: "User",
            column: "NormalizedUsername",
            unique: true);
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropIndex(
            name: "IX_User_NormalizedUsername",
            table: "User");

        migrationBuilder.DropColumn(
            name: "NormalizedUsername",
            table: "User");

        migrationBuilder.AlterColumn<string>(
            name: "Username",
            table: "User",
            type: "text",
            nullable: false,
            oldClrType: typeof(string),
            oldType: "character varying(64)",
            oldMaxLength: 64);

        migrationBuilder.AlterColumn<string>(
            name: "Password",
            table: "User",
            type: "text",
            nullable: false,
            oldClrType: typeof(string),
            oldType: "character varying(100)",
            oldMaxLength: 100);
    }
}
