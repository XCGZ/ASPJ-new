import mysql.connector

class Contact:
    def __init__(self, firstName, lastName, email, message):
        self.firstName = firstName
        self.lastName = lastName
        self.email = email
        self.message = message

    @staticmethod
    def create_table():
        connection = Contact.connect_db()
        cursor = connection.cursor()
        create_table_query = """
        CREATE TABLE IF NOT EXISTS ContactMessages (
            id INT AUTO_INCREMENT PRIMARY KEY,
            firstName VARCHAR(50) NOT NULL,
            lastName VARCHAR(50) NOT NULL,
            email VARCHAR(100) NOT NULL,
            message TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
        cursor.execute(create_table_query)
        connection.commit()
        cursor.close()
        connection.close()

    @staticmethod
    def connect_db():
        return mysql.connector.connect(
            host="localhost",
            user="root",
            password="password",
            database="product_inventory",
            port = 5000
        )

    def save(self):
        connection = Contact.connect_db()
        cursor = connection.cursor()
        insert_data_query = """
        INSERT INTO ContactMessages (firstName, lastName, email, message) VALUES (%s, %s, %s, %s)
        """
        cursor.execute(insert_data_query, (self.firstName, self.lastName, self.email, self.message))
        connection.commit()
        cursor.close()
        connection.close()

    @staticmethod
    def get_all_contacts():
        connection = Contact.connect_db()
        cursor = connection.cursor()
        select_query = "SELECT * FROM ContactMessages"
        cursor.execute(select_query)
        results = cursor.fetchall()
        cursor.close()
        connection.close()
        return results

# Example usage:
# Create the table
Contact.create_table()


# Retrieve and print all contacts
contacts = Contact.get_all_contacts()
for contact in contacts:
    print(contact)
