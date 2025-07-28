#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <math.h>
#include <sys/types.h>
#include <sys/stat.h>

//sudo apt install libssl-dev requerido
#include <openssl/evp.h>
#include <openssl/rand.h>


const int password_length = 16;

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


//completar
int digitos_diff(char *password)
{
  char caracteres[255] = {0};

  for (int i = 0; i < password_length; i++)
  {
    unsigned char c = password[i];

    if(caracteres[c] == 0){
      caracteres[c] = 1;
    }
  }

  int count_diff = 0;
  for(int i = 0 ; i < caracteres[i] != '\0'; i++){
    if(caracteres[i] == 1){
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

  printf("Contraseña %s \n", password);
}

int main(int argc, char *argv[])
{

  mkdir("passwords",0700); 

  char *user = NULL;
  char *service = NULL;
  char *password = malloc((password_length + 1) * sizeof(char));

  srand(time(NULL));

  leer_parametros(argc, argv, &user, &service);

  crear_contrasenia(password);
  double e = entropia(password);

  printf("Password: %s, Entropia = %lf Digitos\n", password,e/log2(10));

  free(password);
  
  return 0;
}
