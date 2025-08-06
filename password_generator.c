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

// Para saber si existe o no el archivo, funciona en Linux
#include <unistd.h>

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

void leer_parametros(int argc, char *argv[], char **user, char **service, unsigned int *update)
{

  printf("Lectura entrando\n");

  for (int i = 1; i < argc; i++)
  {
    if (strcmp(argv[i], "-u") == 0 && i + 1 < argc)
    {
      *user = argv[i + 1];
    }
    else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc)
    {
      *service = argv[i + 1];
    }
    else if (strcmp(argv[i], "--update") == 0 && i < argc)
    {
      printf("Entrando en update\n");
      *update = 1;
      printf("despues de en update\n");
    }
  }

  if (*update != 1)
  {
    *update = 0;
  }
  printf("Lectura realizada\n");
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
char *cifrar_texto(const char *text)
{
  unsigned char key[KEY_SIZE];
  unsigned char iv[IV_SIZE];

  int buffer_size = IV_SIZE + strlen(text) + EVP_MAX_BLOCK_LENGTH;
  unsigned char *ciphertext = malloc(buffer_size);
  if (ciphertext == NULL)
    return NULL;

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
  return (char *)ciphertext;
}

char *descifrar_texto(const char *cifrado, int cifrado_len)
{

  unsigned char key[KEY_SIZE];
  unsigned char *iv = malloc(sizeof(char) * IV_SIZE);

  printf("Cifrado_len %x\n", cifrado_len);

  //me da el error aqui y no se porque.
  memcpy(iv, cifrado, IV_SIZE); // Extraemos IV
  printf("Pinche la huea\n ");

  int texto_cifrado_len = cifrado_len - IV_SIZE;
  unsigned char *texto_plano = malloc(texto_cifrado_len + 1);
  
  printf("texto_cifrado_len %x\n",texto_cifrado_len);

  if (texto_plano == NULL)
    return NULL;

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

void guardar_contrasenia(char *user, char *service, char *password)
{
  char file_name[256];
  snprintf(file_name, sizeof(file_name), "passwords/%s%s.bin", user, service);

  FILE *f = fopen(file_name, "w");
  if (f == NULL)
  {
    perror("Error abriendo el archivo");
    exit(1);
  }

  fputs(password, f);
  fclose(f);
}

void leer_contraseña(char *user, char *service, char *password, int *cifrado_len)
{
  char file_name[256];
  snprintf(file_name, sizeof(file_name), "passwords/%s%s.bin", user, service);

  FILE *f = fopen(file_name, "r");
  if (f == NULL)
  {
    perror("Error abriendo el archivo");
    exit(1);
  }

  fseek(f, 0, SEEK_END);
  long file_size = ftell(f);
  rewind(f);

  password = malloc(file_size);
  if (password == NULL)
  {
    perror("Error al asignar memoria");
    exit(1);
  }

  size_t read_bytes = fread(password, 1, file_size, f);
  if (read_bytes != file_size)
  {
    perror("Error al leer el archivo completo");
    free(password);
    fclose(f);
    exit(1);
  }

  *cifrado_len = read_bytes;

  fclose(f);
}

int main(int argc, char *argv[])
{

  mkdir("passwords", 0700);

  char *user = NULL;
  char *service = NULL;
  char *password = malloc((password_length + 1) * sizeof(char));
  unsigned int *update = malloc(sizeof(unsigned int));

  srand(time(NULL));

  leer_parametros(argc, argv, &user, &service, update);

  char file_name[256];
  snprintf(file_name, sizeof(file_name), "passwords/%s%s.bin", user, service);

  printf("Update : %x  !update: %x\n", *update, !*update);
  printf("If %x\n", *update == 1 || access(file_name, F_OK) != 0);

  if (*update == 0 && access(file_name, F_OK) == 0)
  {
    printf("Entrando else\n");

    char *cifrado = NULL;
    printf("Antes de leer\n");

    int *len = malloc(sizeof(int));
    leer_contraseña(user, service, cifrado, len);
    printf("Despues de leer\n");

    printf("Cifrado_len %x\n", *len);

    password = descifrar_texto(cifrado, *len);
    printf("Password DEScifrada: %s\n", password);
  }
  else
  {
    crear_contrasenia(password);

    double e = entropia(password);
    printf("Password: %s, Entropia = %lf Digitos\n", password, e / log2(10));

    char *cifrado = cifrar_texto(password);

    guardar_contrasenia(user, service, cifrado);
    free(cifrado);
  }

  // leer_contraseña(user, service, password);
  // printf("%s\n", password);
  /*  printf("Password cifrada:\n");

    int i = 0;
    while (cifrado[i] != '\0')
    {
      printf("%02x ", cifrado[i]);
      i++;
    }
    printf("\n");
  */

  free(password);

  return 0;
}

/*
como compilar
"gcc password_generator.c -o password_generator -lcrypto -lm"
 */