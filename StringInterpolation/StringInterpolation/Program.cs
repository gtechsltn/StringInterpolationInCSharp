using System;
using System.Data.SqlClient;

namespace StringInterpolation
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            // Calling the method with malicious input
            ExecuteQuery("Maria' OR '1'='1'");

            // Calling the method with safe input.
            ExecuteSafeQuery("Maria");

            Console.WriteLine();
            Console.Write("DONE. Press any key to exit...");
            Console.ReadKey();
        }

        /// <summary>
        /// This method is assumed to receive user input.
        /// ===========================================================================================================================================
        /// In the example above, the SQL query is constructed directly with string interpolation, which can lead to code injection.
        /// A malicious user might provide input such as "Maria' OR '1'='1", resulting in an SQL query that returns all records from the Users table:
        ///   SELECT * FROM Users WHERE vcUserName = 'Maria' OR '1'='1'
        /// This compromises the security of the database, as it allows the user to bypass the query conditions and accessunauthorized data.
        /// </summary>
        /// <param name="username"></param>
        private static void ExecuteQuery(string username)
        {
            // String interpolation used directly in the SQL query.
            string query = $"SELECT * FROM Users WHERE vcUserName = '{username}'";

            Console.WriteLine($"query: {query}");

            // Creates an SQL command with the interpolated string.
            using (SqlConnection connection = new SqlConnection("Data Source=.;Initial Catalog=mssql;Integrated Security=SSPI;Connect Timeout=30;Pooling=True;Max Pool Size=10;"))
            {
                SqlCommand command = new SqlCommand(query, connection);
                try
                {
                    connection.Open();
                    SqlDataReader reader = command.ExecuteReader();
                    while (reader.Read())
                    {
                        Console.WriteLine($"uidUser: {reader["uidUser"]}, vcUserName: {reader["vcUserName"]}");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error: {ex.Message}");
                }
            }
        }

        private static void ExecuteSafeQuery(string username)
        {
            // SQL query with parameters.
            string query = $"SELECT * FROM Users WHERE vcUserName = @Name";

            using (SqlConnection connection = new SqlConnection("Data Source=.;Initial Catalog=mssql;Integrated Security=SSPI;Connect Timeout=30;Pooling=True;Max Pool Size=10;"))
            {
                SqlCommand command = new SqlCommand(query, connection);
                command.Parameters.AddWithValue("@Name", username);

                try
                {
                    connection.Open();
                    SqlDataReader reader = command.ExecuteReader();

                    while (reader.Read())
                    {
                        Console.WriteLine($"uidUser: {reader["uidUser"]}, vcUserName: {reader["vcUserName"]}");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error: {ex.Message}");
                }
            }
        }
    }
}