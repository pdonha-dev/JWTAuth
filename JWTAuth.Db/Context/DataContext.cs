using JWTAuth.Entities;
using Microsoft.EntityFrameworkCore;

namespace JWTAuth.Db.Context
{
    public class DataContext : DbContext
    {
        public DataContext(DbContextOptions<DataContext> options) : base(options) { }

        public DbSet<User> Users => Set<User>();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            var user = modelBuilder.Entity<User>();
            user.ToTable("User");
            user.HasKey(x => x.UserId);
            user.Property(x => x.Username).HasMaxLength(64).IsRequired();
            user.Property(x => x.NormalizedUsername).HasMaxLength(64).IsRequired();
            user.Property(x => x.PasswordHash).HasColumnName("Password").HasMaxLength(100).IsRequired();
            user.HasIndex(x => x.NormalizedUsername).IsUnique();
        }
    }
}
