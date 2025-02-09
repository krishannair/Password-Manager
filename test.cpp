#include <openssl/rand.h>
#include <vector>
#include <iostream>
#include <fstream>
#include <sqlite3.h>
#include <FL/Fl.H>
#include <FL/Fl_Window.H>
#include <FL/Fl_Input.H>
#include <FL/Fl_Button.H>
#include <FL/Fl_Multiline_Output.H>
#include <tuple>


#define AES_KEY_SIZE 32  // 256-bit key
#define AES_IV_SIZE 16   // 128-bit IV
#define AES_BLOCK_SIZE 16
#define SALT_SIZE 16
#define PBKDF2_ITERATIONS 100000

void save_to_db(const std::string& database_name, const std::vector <unsigned char>& encrypted_password, const std::vector <unsigned char>& iv) {
    sqlite3* db;
    int rc = sqlite3_open(database_name.c_str(), &db);
    if(rc != SQLITE_OK) {
        std::cerr << "Cannot open database" << sqlite3_errmsg(db) << std::endl;
        exit(1);
    }
    else {
        std::cout << "Database opened successfully!" << std::endl;
    }

    const char* create_table_sql = "CREATE TABLE IF NOT EXISTS passwords ("
                                   "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                //    "site TEXT NOT NULL, "
                                   "iv BLOB NOT NULL, "
                                   "encrypted_password BLOB NOT NULL);";

    char* errMsg = nullptr;
    rc = sqlite3_exec(db, create_table_sql, nullptr, 0, &errMsg);
    if(rc != SQLITE_OK) {
        std::cerr << "SQL error: " << errMsg << std::endl;
        sqlite3_free(errMsg);
        exit(1);
    }
    else {
        std::cout << "Table created successfully" << std::endl;
    }
    std::string insert_sql = "INSERT INTO passwords (iv, encrypted_password) VALUES (?, ?, ?)";
    sqlite3_stmt* stmt;
    rc = sqlite3_prepare_v2(db, insert_sql.c_str(), -1, &stmt, nullptr);
    if(rc != SQLITE_OK) {
        std::cerr << "Database failed preparation" << sqlite3_errmsg(db) << std::endl;
        exit(1);
    }
    // sqlite3_bind_text(stmt, 1, site.data(), site.size(), SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 1, iv.data(), iv.size(), SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, encrypted_password.data(), encrypted_password.size(), SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if(rc != SQLITE_DONE) {
        std::cerr << "Execution Failed" << sqlite3_errmsg(db) << std::endl;
    }
    else {
        std::cout << "Password saved to database" << std::endl;
    }

    sqlite3_finalize(stmt);
}

void save_to_file(const std::string& filename, const std::vector<unsigned char>& data) {
    std::ofstream file(filename, std::ios::binary);
    file.write((char*)data.data(), data.size());
    file.close();
}

// Redundant after addition of database
// void save_password(const std::string& filename, const std::vector<unsigned char>& encrypted_password, const std::vector<unsigned char>& iv) {
//     std::ofstream file(filename, std::ios::binary | std::ios::app);

//     if(!file) {
//         std::cerr << "Error opening file" << std::endl;
//         return;
//     }

//     uint32_t length = encrypted_password.size();

//     file.write(reinterpret_cast<const char*>(iv.data()), iv.size());
//     file.write(reinterpret_cast<const char*>(&length), sizeof(length));
//     file.write(reinterpret_cast<const char*>(encrypted_password.data()), length);

//     file.close();
// }

void generate_iv(std::vector<unsigned char>& iv) {
    iv.resize(AES_IV_SIZE);

    if (!RAND_bytes(iv.data(), AES_IV_SIZE)) {
        std::cerr << "Error generating AES IV." << std::endl;
        exit(EXIT_FAILURE);
    }
}

std::string decrypt_aes(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<unsigned char> plaintext(ciphertext.size() + AES_BLOCK_SIZE);
    int len, plaintext_len;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, (unsigned char*)ciphertext.data(), ciphertext.size());
    plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    plaintext.resize(plaintext_len);
    return std::string(plaintext.begin(), plaintext.end());
}


std::vector<std::tuple<std::vector<unsigned char>, std::vector<unsigned char>>> load_from_db(const std::string& database_name) {
    sqlite3* db;
    int rc = sqlite3_open((database_name).c_str(), &db);
    if(rc) {
        std::cerr << "Cannot open database" << sqlite3_errmsg(db) << std::endl;
        exit(1);
    }
    else {
        std::cout << "Database opened successfully!" << std::endl;
    }
    std::vector<std::tuple<std::vector<unsigned char>, std::vector<unsigned char>>> password_entries;
    const char* create_table_sql = "CREATE TABLE IF NOT EXISTS passwords ("
                                   "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                //    "site BLOB NOT NULL, "
                                   "iv BLOB NOT NULL, "
                                   "encrypted_password BLOB NOT NULL);";

    char* errMsg = nullptr;
    rc = sqlite3_exec(db, create_table_sql, nullptr, 0, &errMsg);
    if(rc != SQLITE_OK) {
        std::cerr << "SQL error: " << errMsg << std::endl;
        sqlite3_free(errMsg);
        exit(1);
    }
    else {
        std::cout << "Table created successfully" << std::endl;
    }

    std::string select_sql = "SELECT iv, encrypted_password FROM passwords";
    sqlite3_stmt* stmt;
    rc = sqlite3_prepare_v2(db, select_sql.c_str(), -1, &stmt, nullptr);
    if(rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        exit(1);
    }
    while(sqlite3_step(stmt) == SQLITE_ROW) {  // Loop over each row of the result
        // const void* site_data = sqlite3_column_blob(stmt, 0);
        // int site_size = sqlite3_column_bytes(stmt, 0);
        const void* iv_data = sqlite3_column_blob(stmt, 0);  // Retrieve IV as BLOB
        int iv_size = sqlite3_column_bytes(stmt, 0);  // Get the size of the IV
        const void* encrypted_password_data = sqlite3_column_blob(stmt, 1);  // Retrieve encrypted password
        int encrypted_password_size = sqlite3_column_bytes(stmt, 1);  // Get the size of the encrypted password

        // std::string site((unsigned char*)site_data,(unsigned char*)site_data + site_size);
        std::vector<unsigned char> iv((unsigned char*)iv_data, (unsigned char*)iv_data + iv_size);
        std::vector<unsigned char> encrypted_password((unsigned char*)encrypted_password_data, (unsigned char*)encrypted_password_data + encrypted_password_size);

        // Now you can decrypt the password using your decryptAES function
        // std::string decryptedPassword = decrypt_aes(encrypted_password, key, iv);
        // std::cout << "Decrypted password: " << decryptedPassword << std::endl;
        password_entries.push_back(std::make_tuple(iv, encrypted_password));
    }
    sqlite3_finalize(stmt);  // Clean up after using the statement
    sqlite3_close(db);
    return password_entries;
}
// Redundant after addition of database
// void load_password(const std::string& filename, const std::vector<unsigned char>& key) {
//     std::ifstream file(filename, std::ios::binary);
//     if (!file) {
//         std::cerr << "Error opening file" << std::endl;
//         return; 
//     }

//     while (file) {
//         std::vector<unsigned char> iv(16);
//         uint32_t length;

//         file.read(reinterpret_cast<char*>(iv.data()), iv.size());
//         if (file.eof())
//             break;
        
//         file.read(reinterpret_cast<char*>(&length), sizeof(length));
//         if(file.eof())
//             break;
        
//         std::vector<unsigned char> encrypted_password(length);
//         file.read(reinterpret_cast<char*>(encrypted_password.data()), length);

//         std::string decryptedPassword = decrypt_aes(encrypted_password, key, iv);
//         std::cout << "Decrypted: " << decryptedPassword << std::endl;
//     }
// }

void load_salt(const std::string& filename, std::vector<unsigned char>& salt) {
    std::ifstream file(filename, std::ios::binary);
    salt.resize(SALT_SIZE);
    file.read((char*)salt.data(), SALT_SIZE);
    file.close();
}

void generate_salt(std::vector<unsigned char>& salt)
{
    salt.resize(SALT_SIZE);
    RAND_bytes(salt.data(), SALT_SIZE);  // Generating random salt (this makes every encrytion unique even if it is the same password)
}



void derive_key(const std::string& password, std::vector<unsigned char>& key, std::vector<unsigned char>& salt) {
    key.resize(AES_KEY_SIZE);


    // Deriving key from entered password
    PKCS5_PBKDF2_HMAC(password.c_str(), password.size(), salt.data(), salt.size(), PBKDF2_ITERATIONS, EVP_sha256(), key.size(), key.data());
}

std::pair<std::vector<unsigned char>, std::vector<unsigned char>> encrypt_aes(const std::string& plaintext, const std::vector<unsigned char>& key, std::vector<unsigned char>& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
    int len, ciphertext_len;
    generate_iv(iv);
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (unsigned char*)plaintext.data(), plaintext.size());
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    ciphertext.resize(ciphertext_len); // Trim extra space
    return {ciphertext, iv};
}

void load_into_ui(Fl_Multiline_Output *output) {
    std::string site, encrypted_password;
    std::string allPasswords;
    std::string masterkey = "abcd1234";
    std::vector<unsigned char> key, salt, iv;
    std::ifstream file("salt.dat", std::ios::binary);
    if(!file) {
        std::cout << "Unable to find salt file." << std::endl;
    }
    else {
        load_salt("salt.dat", salt);
    }
    derive_key(masterkey, key, salt);

    std::vector<std::tuple<std::vector<unsigned char>, std::vector<unsigned char>>> passwords = load_from_db("passwords.db");
    for (const auto& entry : passwords) {
        // std::string site = std::get<0>(entry);
        std::vector<unsigned char> iv = std::get<0>(entry);
        std::vector<unsigned char> encrypted_password = std::get<1>(entry);

        // Decrypt password using the stored IV and key
        std::string decrypted_password = decrypt_aes(encrypted_password, key, iv);
        allPasswords += site + ": " + decrypted_password + "\n";
    }
    output->value(allPasswords.empty() ? "No passwords saved." : allPasswords.c_str());
}

void save_from_ui(Fl_Input *siteInput, Fl_Input *passInput, Fl_Multiline_Output *output) {
    std::string site = siteInput->value();
    std::string password = passInput->value();
    std::string masterkey = "abcd1234";
    if (site.empty() || password.empty()) {
        output->value("Please enter both site and the password");
        return;
    }
    std::vector<unsigned char> key, salt, iv;
    std::ifstream file("salt.dat", std::ios::binary);
    if(!file) {
        generate_salt(salt);
        save_to_file("salt.dat", salt);
    }
    else {
        load_salt("salt.dat", salt);
    }
    derive_key(masterkey, key, salt);
    std::pair<std::vector<unsigned char> , std::vector<unsigned char>> encPassAndIV = encrypt_aes(password, key, iv);
    save_to_db("passwords.db", encPassAndIV.first, encPassAndIV.second);
    output->value("Password saved!");
    siteInput->value(""); 
    passInput->value(""); 
}

int main() {

    // Main Window
    Fl_Window *window = new Fl_Window(400, 300, "Password Manager");

    // Input Fields
    Fl_Input *siteInput = new Fl_Input(100, 20, 250, 30, "Site:");
    Fl_Input *passInput = new Fl_Input(100, 60, 250, 30, "Password:");
    passInput->type(FL_SECRET_INPUT);

    // Buttons
    Fl_Button *saveButton = new Fl_Button(50, 110, 130, 30, "Save Password");
    Fl_Button *loadButton = new Fl_Button(220, 110, 130, 30, "Show Password");

    // Output Area
    Fl_Multiline_Output *output = new Fl_Multiline_Output(50, 160, 300, 100, "");

    // Button Callbacks
    saveButton->callback((Fl_Callback*)save_from_ui, (void *)siteInput);
    saveButton->callback((Fl_Callback*)save_from_ui, (void *)passInput);
    saveButton->callback((Fl_Callback*)save_from_ui, (void *)output);

    loadButton->callback((Fl_Callback*)load_into_ui, (void *)output);

    window->end();
    window->show();
    return Fl::run();

    // std::vector<unsigned char> key, salt, iv;
    // std::cout << "Enter the masterkey: " << std::endl;
    // std::string masterkey;
    // std::cin >> masterkey;
    // std::cin.ignore();  // This will ignore the leftover newline character
    // std::cout << "Your masterkey is: " << masterkey << std::endl;
    // std::string data;

// Only for 1st time
    // generate_salt(salt);
    // save_to_file("salt.dat", salt);

// Always after
//     load_salt("salt.dat", salt);

//     derive_key(masterkey, key, salt);

// // Encryption
//     std::cout << "Enter data to be encrypted: " << std::endl;
//     std::getline(std::cin, data);
//     std::pair<std::vector<unsigned char> , std::vector<unsigned char>> encPassAndIV = encrypt_aes(data, key, iv);
//     save_to_db("passwords.db", encPassAndIV.first, encPassAndIV.second);

// Decryption
    // std::cout << "Database file name of data decryption: " << std::endl;
    // std::string filename;
    // std::cin >> filename;
    // load_from_db(filename, key);

    return 0;
}
