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

struct UIData {
    Fl_Input* siteInput;
    Fl_Input* passInput;
    Fl_Multiline_Output* output;
    Fl_Input* masterInput;
};

void save_to_db(const std::string& database_name, const std::string& site, const std::vector <unsigned char>& encrypted_password, const std::vector <unsigned char>& iv) {
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
                                   "site TEXT NOT NULL, "
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
    std::string insert_sql = "INSERT INTO passwords (site, iv, encrypted_password) VALUES (?, ?, ?)";
    sqlite3_stmt* stmt;
    rc = sqlite3_prepare_v2(db, insert_sql.c_str(), -1, &stmt, nullptr);
    if(rc != SQLITE_OK) {
        std::cerr << "Database failed preparation" << sqlite3_errmsg(db) << std::endl;
        exit(1);
    }
    sqlite3_bind_text(stmt, 1, site.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, iv.data(), iv.size(), SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 3, encrypted_password.data(), encrypted_password.size(), SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if(rc != SQLITE_DONE) {
        std::cerr << "Execution Failed" << sqlite3_errmsg(db) << std::endl;
    }
    else {
        std::cout << "Password saved to database" << std::endl;
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
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


std::vector<std::tuple<std::string, std::vector<unsigned char>, std::vector<unsigned char>>> load_from_db(const std::string& database_name) {
    sqlite3* db;
    int rc = sqlite3_open((database_name).c_str(), &db);
    if(rc) {
        std::cerr << "Cannot open database" << sqlite3_errmsg(db) << std::endl;
        exit(1);
    }
    else {
        std::cout << "Database opened successfully!" << std::endl;
    }
    std::vector<std::tuple<std::string, std::vector<unsigned char>, std::vector<unsigned char>>> password_entries;

    std::string select_sql = "SELECT site, iv, encrypted_password FROM passwords";
    sqlite3_stmt* stmt;
    rc = sqlite3_prepare_v2(db, select_sql.c_str(), -1, &stmt, nullptr);
    if(rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        exit(1);
    }
    while(sqlite3_step(stmt) == SQLITE_ROW) {  // Loop over each row of the result
        std::string site = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        const void* iv_data = sqlite3_column_blob(stmt, 1);  // Retrieve IV as BLOB
        int iv_size = sqlite3_column_bytes(stmt, 1);  // Get the size of the IV
        const void* encrypted_password_data = sqlite3_column_blob(stmt, 2);  // Retrieve encrypted password
        int encrypted_password_size = sqlite3_column_bytes(stmt, 2);  // Get the size of the encrypted password
        
        std::vector<unsigned char> iv((unsigned char*)iv_data, (unsigned char*)iv_data + iv_size);
        std::vector<unsigned char> encrypted_password((unsigned char*)encrypted_password_data, (unsigned char*)encrypted_password_data + encrypted_password_size);

        // Now you can decrypt the password using your decryptAES function
        // std::string decryptedPassword = decrypt_aes(encrypted_password, key, iv);
        // std::cout << "Decrypted password: " << decryptedPassword << std::endl;
        password_entries.push_back(std::make_tuple(site, iv, encrypted_password));
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

void load_into_ui(Fl_Widget*, void* data) {
    UIData* uiData = static_cast<UIData*>(data);
    std::string masterkey = uiData->masterInput->value();
    uiData->output->value("");  // Clear previous output
    std::string site, encrypted_password;
    std::string allPasswords="";
    std::vector<unsigned char> key, salt, iv;
    std::ifstream file("salt.dat", std::ios::binary);
    if(!file) {
        std::cout << "Unable to find salt file." << std::endl;
        return;
    }
    else {
        load_salt("salt.dat", salt);
    }
    std::cout << "6" << std::endl;
    derive_key(masterkey, key, salt);
    std::cout << "7" << std::endl;
    std::vector<std::tuple<std::string, std::vector<unsigned char>, std::vector<unsigned char>>> passwords = load_from_db("passwords.db");
    std::cout << "8" << std::endl;
    for (const auto& entry : passwords) {
        std::string site = std::get<0>(entry);
        std::vector<unsigned char> iv = std::get<1>(entry);
        std::vector<unsigned char> encrypted_password = std::get<2>(entry);

        // Decrypt password using the stored IV and key
        std::string decrypted_password = decrypt_aes(encrypted_password, key, iv);
        allPasswords += "Site:" + site + "\nPassword:" + decrypted_password + "\n\n";
        std::cout << decrypted_password << std::endl;   
    }
    std::cout << "9" << std::endl;
    std::cout << allPasswords << std::endl;
    uiData->output->value(allPasswords.empty() ? "No passwords saved." : allPasswords.c_str());
    std::cout << "10" << std::endl;
}

void save_from_ui(Fl_Widget*, void* data) {
    UIData* uiData = static_cast<UIData*>(data);
    const std::string site = uiData->siteInput->value();
    const std::string password = uiData->passInput->value();
    const std::string masterkey = uiData->masterInput->value();
    std::cout << "0" << std::endl;
    std::cout << "0.1" << std::endl;
    std::cout << "0.2" << std::endl;
    std::cout << "1" << std::endl;
    if (site.empty() || password.empty()) {
        uiData->output->value("Please enter both site and the password");
        return;
    }
    std::cout << "2" << std::endl;
    std::vector<unsigned char> key, salt, iv;
    std::ifstream file("salt.dat", std::ios::binary);
    if(!file) {
        generate_salt(salt);
        save_to_file("salt.dat", salt);
    }
    else {
        load_salt("salt.dat", salt);
    }
    std::cout << "3" << std::endl;

    derive_key(masterkey, key, salt);
    std::pair<std::vector<unsigned char> , std::vector<unsigned char>> encPassAndIV = encrypt_aes(password, key, iv);
    std::cout << "4" << std::endl;
    save_to_db("passwords.db", site, encPassAndIV.first, encPassAndIV.second);
    std::cout << "5" << std::endl;
    uiData->output->value("Password saved!");
    uiData->siteInput->value(""); 
    uiData->passInput->value(""); 
}

int main() {

    // Main Window
    Fl_Window *window = new Fl_Window(600, 500, "Password Manager");

    // Input Fields
    UIData uiData;
    uiData.masterInput = new Fl_Input(100, 20, 350, 30, "Masterkey:");
    uiData.siteInput = new Fl_Input(100, 60, 350, 30, "Site:");
    uiData.passInput = new Fl_Input(100, 100, 350, 30, "Password:");

    uiData.masterInput->type(FL_SECRET_INPUT);

    // Buttons
    Fl_Button *saveButton = new Fl_Button(100, 150, 130, 30, "Save Password");
    Fl_Button *loadButton = new Fl_Button(300, 150, 130, 30, "Show Password");

    // Output Area
    uiData.output = new Fl_Multiline_Output(50, 200, 400, 200, "");

    saveButton->callback(save_from_ui, &uiData);
    loadButton->callback(load_into_ui, &uiData);

    window->end();
    window->show();
    return Fl::run();

    return 0;
}
