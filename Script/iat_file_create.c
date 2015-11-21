/*
 * Creato da Giacomo Pandini
 *
 * Il programma analizza le informazioni relative ad un flusso dati presenti in un file appositamente creato
 * attraverso il comando split di D-ITG. Da quelle informazioni calcola l'inter arrival time per ogni pacchetto
 * del flusso. Scrive poi, per ogni pacchetto, il ritardo dal pacchetto iniziale e l'inter arrival time.
 *
 *
 * Utilizzo:
 * iat_file_create <file di input> <file di output>
 */

#include <stdio.h>
#include <stdlib.h>


float diff_Time(int o_h, int o_m, float o_s, int n_h, int n_m, float n_s ) //calcola la differenza in secondi tra due record temporali divisi in ore, minuti e secondi. I primi tre valori sono relativi al valore più vecchio, gli altri tre a quello più nuovo
{
    int res=n_h - o_h;
    if( (res)>0 )
    {
        n_m=n_m+60*res;
    }
    res=n_m - o_m;
    if( (res)>0 )
    {
        n_s=n_s+60*res;
    }
    return (n_s - o_s);
}

//Passo in ingresso il nome del file da cui legge le informazioni e il nome del file in cui scrive il risultato
int main(int argc, char *argv[])
{
    FILE* i;
    FILE* o;
    
    if(argc != 3) //Controllo argomenti in ingresso
    {
        printf("Creazione di file leggibile per la realizzazione del grafico di inter arrival time.\nUsage: iat_file_create <file2read> <file2write>\n");
        exit(1);
    }
    
    if ((i = fopen(argv[1], "r")) == NULL) //Apro file di lettura
    {
        printf("Errore apertura file di lettura.\n");
        exit(1);
    }
    if((o = fopen(argv[2], "w")) == NULL) //Apro file di scrittura
    {
        printf("Errore apertura file di scrittura.\n");
        exit(1);
    }

    //Variabili di supporto
    int hi;
    float hf;
    
    //Record temporale vecchio
    float o_sec;
    int o_min;
    int o_hour;
    //Record temporale nuovo
    float n_sec;
    int n_min;
    int n_hour;
    //Record temporale iniziale
    float s_sec;
    int s_min;
    int s_hour;
    
    fscanf(i,"%d\t%d\t%d\t%f\t%d\t%d\%f\t%d\n",&hi,&s_hour,&s_min,&s_sec,&o_hour,&o_min,&o_sec,&hi); //Valori del primo record
    
    while(!feof(i)) //Scorre tutto il file
    {
        int pack;
        fscanf(i,"%d\t%d\t%d\t%f\t%d\t%d\%f\t%d\n",&pack,&hi,&hi,&hf,&n_hour,&n_min,&n_sec,&hi); //per ogni record mi salvo i valori
        
        //DEBUG
        //printf("New %d %d %f - Old %d %d %f\n = %f\n",n_hour,n_min,n_sec,o_hour,o_min,o_sec,diff_Time(o_hour,o_min,o_sec,n_hour,n_min,n_sec));
        
        fprintf(o,"%d\t%f\t%f\n",pack,diff_Time(s_hour,s_min,s_sec,n_hour,n_min,n_sec),diff_Time(o_hour,o_min,o_sec,n_hour,n_min,n_sec)); //Scrivo su un file la differenza l'inter arrival time ottenuto per ogni pacchetto, calcolo il tempo in relazione alla differenza tra l'arrivo del pacchetto e il primo pacchetto arrivato
        
        // Mi salvo i valori appena esaminati per il prossimo confronto
        o_sec=n_sec;
        o_min=n_min;
        o_hour=n_hour;
    }
    //Chiudo i file aperti
    fclose(i);
    fclose(o);

    return 0;
}