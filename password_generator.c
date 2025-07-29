#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <math.h>
#include <sys/types.h>
#include <sys/stat.h>

// sudo apt install libssl-dev requerido
#include <openssl/evp.h>
#include <openssl/rand.h>

const int password_length = 16;
const int SALT_SIZE = 16;
const int KEY_SIZE = 32;
const int IV_SIZE = 16;

const char *contraseña = "contraseña_huevon";

// hacer una estructura de datos.
typedef struct Dodo
{
  char caracter;
  struct Nodo *siguiente;
} Nodo;

void leer_parametros(int argc, char *argv[], char **user, char **service)
{

  for (int i = 1; i < argc; i++)
  {
    if (strcmp(argv[i], "-u") == 0 && i + 1 < argc)
    {
      // printf("Usuario %s \n", argv[i + 1]);
      *user = argv[i + 1];
    }
    else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc)
    {
      // printf("Servicio %s \n", argv[i + 1]);
      *service = argv[i + 1];
    }
  }
}

/**
 * Entropia = log_2(R^L) = L * log_2(R^)  formula en bits
 * Siendo R la variedad de caracteres utilizados en la contraseña
 * Siendo L la longitud o número de caracteres.
 * Mientras mas variedad de caracteres más segura es ya que aumenta la base.
 *
 * Se calcula en bits o digitos (Digitos = bits/(log_2(10)) )
 * 1 Dígito de entropía es equivalente a 10 posibilidades.
 */

// completar
int digitos_diff(char *password)
{
  char caracteres[255] = {0};

  for (int i = 0; i < password_length; i++)
  {
    unsigned char c = password[i];

    if (caracteres[c] == 0)
    {
      caracteres[c] = 1;
    }
  }

  int count_diff = 0;
  for (int i = 0; i < caracteres[i] != '\0'; i++)
  {
    if (caracteres[i] == 1)
    {
      count_diff++;
    }
  }

  return count_diff;
}

double entropia(char *password)
{
  return (password_length * log2(digitos_diff(password)));
}

void crear_contrasenia(char *password)
{
  for (int i = 0; i < password_length; i++)
  {
    char caracter_pass = (char)(33 + rand() % (126 - 33 + 1));
    password[i] = caracter_pass;
  }
  password[password_length] = '\0'; // para que el sigueinte comando printf %s sepa donde termina.
}

// Arreglarlo para añadir el salt y el iv.
char *cifrar_texto(const char *text, int *len_No_defi)
{
    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];

    int buffer_size = IV_SIZE + strlen(text) + EVP_MAX_BLOCK_LENGTH; 
    unsigned char *ciphertext = malloc(buffer_size);
    if (ciphertext == NULL) return NULL;

    RAND_bytes(iv, sizeof(iv));
    PKCS5_PBKDF2_HMAC(contraseña, strlen(contraseña), NULL, 0, 100000, EVP_sha256(), KEY_SIZE, key);

    memcpy(ciphertext, iv, IV_SIZE); // Guardamos IV al principio

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    int len, ciphertext_len;
    EVP_EncryptUpdate(ctx, ciphertext + IV_SIZE, &len, (unsigned char *)text, strlen(text));
    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext + IV_SIZE + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    *len_No_defi = IV_SIZE + ciphertext_len; // Total con IV

    return (char *)ciphertext;
}

char *descifrar_texto(const char *cifrado, int cifrado_len)
{
    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];

    memcpy(iv, cifrado, IV_SIZE); // Extraemos IV

    int texto_cifrado_len = cifrado_len - IV_SIZE;
    unsigned char *texto_plano = malloc(texto_cifrado_len + 1);
    if (texto_plano == NULL) return NULL;

    PKCS5_PBKDF2_HMAC(contraseña, strlen(contraseña), NULL, 0, 100000, EVP_sha256(), KEY_SIZE, key);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    int len, texto_plano_len;
    EVP_DecryptUpdate(ctx, texto_plano, &len, (unsigned char *)cifrado + IV_SIZE, texto_cifrado_len);
    texto_plano_len = len;

    EVP_DecryptFinal_ex(ctx, texto_plano + len, &len);
    texto_plano_len += len;
    texto_plano[texto_plano_len] = '\0';

    EVP_CIPHER_CTX_free(ctx);

    return (char *)texto_plano;
}


void guardar_contrasenia(char *user, char *service, char *password) {
    char file_name[256];
    snprintf(file_name, sizeof(file_name), "passwords/%s%s.bin", user, service);

    FILE *f = fopen(file_name, "w");
    if (f == NULL) {
        perror("Error abriendo el archivo");
        exit(1);
    }

    fputs(password, f);
    fclose(f);
}


void leer_contraseña(char *user, char *service, char *password) {
    char file_name[256];
    snprintf(file_name, sizeof(file_name), "passwords/%s%s.bin", user, service);

    FILE *f = fopen(file_name, "r");
    if (f == NULL) {
        perror("Error abriendo el archivo");
        exit(1);
    }

    if (fgets(password, password_length + 2, f) != NULL) {
        password[strcspn(password, "\n")] = '\0';
    }

    fclose(f);
}

int main(int argc, char *argv[])
{

  mkdir("passwords", 0700);

  char *user = NULL;
  char *service = NULL;
  char *password = malloc((password_length + 1) * sizeof(char));

  srand(time(NULL));

  leer_parametros(argc, argv, &user, &service);

  crear_contrasenia(password);
  double e = entropia(password);

  printf("Password: %s, Entropia = %lf Digitos\n", password, e / log2(10));

  //guardar_contrasenia(user, service, password);
  //leer_contraseña(user, service, password);
  //printf("%s\n", password);
  int len_prueba;
  char *cifrado = cifrar_texto(password, &len_prueba);
  printf("len_pass %lx, len_cifrado %x\n", strlen(password), len_prueba);
  printf("Password cifrada:\n");

  int i = 0;
  while (cifrado[i] != '\0')
  {
    printf("%02x ", cifrado[i]);
    i++;
  }
  printf("\n");

  char *texto_plano = descifrar_texto(cifrado, len_prueba);
  

  printf("Password DEScifrada: %s\n", texto_plano);

  free(cifrado);
  free(password);

  return 0;
}

/*
como compilar
"gcc password_generator.c -o password_generator -lcrypto -lm"
 */