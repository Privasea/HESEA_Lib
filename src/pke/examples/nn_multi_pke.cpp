// ----------------------------------------------------------------------------|
// Title      : Fast Homomorphic Evaluation of Deep Discretized Neural Networks
// Project    : Demonstrate Fast Fully Homomorphic Evaluation of Encrypted Inputs
//              using Deep Discretized Neural Networks hence preserving Privacy
// ----------------------------------------------------------------------------|
// File       : nn.cpp
// Authors    : Florian Bourse      <Florian.Bourse@ens.fr>
//              Michele Minelli     <Michele.Minelli@ens.fr>
//              Matthias Minihold   <Matthias.Minihold@RUB.de>
//              Pascal Paillier     <Pascal.Paillier@cryptoexperts.com>
//
// Reference  : TFHE: Fast Fully Homomorphic Encryption Library over the Torus
//              https://github.com/tfhe
// ----------------------------------------------------------------------------|
// Description:
//     Showcases how to efficiently evaluate privacy-perserving neural networks.
// ----------------------------------------------------------------------------|
// Revisions  :
// Date        Version  Description
// 2017-11-16  0.3.0    Version for github, referenced by ePrint paper
// ----------------------------------------------------------------------------|


// Includes
#include <bits/types/time_t.h>
#include <stdio.h>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <iostream>
#include <iomanip>
#include <cstdlib>
#include <cmath>
#include <fstream>
#include <memory>
#include <ostream>
#include <string>
#include "math/backend.h"
#include <sys/time.h>
// Multi-processing
#include <sys/wait.h>
#include <unistd.h>
#include <ctime>

//! binfhecontext
#define PROFILE
#include <vector>
// #include "binfhecontext.h"
#include "hesea.h"
using namespace lbcrypto;


// Defines
#define VERBOSE 1
#define STATISTICS true
#define WRITELATEX false
#define N_PROC 1

// Security constants
#define SECLEVEL 80
#define SECNOISE true
#define SECALPHA pow(2., -20)
#define SEC_PARAMS_STDDEV    pow(2., -30)
#define SEC_PARAMS_n  600                   ///  LweParams
#define SEC_PARAMS_N 1024                   /// TLweParams
#define SEC_PARAMS_k    1                   /// TLweParams
#define SEC_PARAMS_BK_STDDEV pow(2., -36)   /// TLweParams
#define SEC_PARAMS_BK_BASEBITS 10           /// TGswParams
#define SEC_PARAMS_BK_LENGTH    3           /// TGswParams
#define SEC_PARAMS_KS_STDDEV pow(2., -25)   /// Key Switching Params
#define SEC_PARAMS_KS_BASEBITS  1           /// Key Switching Params
#define SEC_PARAMS_KS_LENGTH   18           /// Key Switching Params

// The expected topology of the provided neural network is 256:30:10
#define NUM_NEURONS_LAYERS 3
#define NUM_NEURONS_INPUT  256
#define NUM_NEURONS_HIDDEN 30
#define NUM_NEURONS_OUTPUT 10

//! how many pics
#define CARD_TESTSET 2

// Files are expected in the executable's directory
#define PATH_TO_FILES       "buildotests/test/" //TODO FIXME!
#define FILE_TXT_IMG        "../../../weights-and-biases/txt_img_test.txt"
#define FILE_TXT_BIASES     "../../../weights-and-biases/txt_biases.txt"
#define FILE_TXT_WEIGHTS    "../../../weights-and-biases/txt_weights.txt"
#define FILE_TXT_LABELS     "../../../weights-and-biases/txt_labels.txt"
#define FILE_LATEX          "results_LaTeX.tex"
#define FILE_STATISTICS     "results_stats.txt"

// Tweak neural network
#define THRESHOLD_WEIGHTS  9
#define THRESHOLD_SCORE -100

#define MSG_SLOTS    700
#define TORUS_SLOTS  400


using namespace std;

void deleteTensor(int*** tensor, int dim_mat, const int* dim_vec);
void deleteMatrix(int**  matrix, int dim_mat);




int main(int argc, char **argv)
{
    // Security
    const bool noisyLWE      = SECNOISE;

    // Input data
    const int n_images = CARD_TESTSET;
    const int slice = (n_images+N_PROC-1)/N_PROC;

    // Network specific
    const int num_wire_layers = NUM_NEURONS_LAYERS - 1;
    const int num_neuron_layers = NUM_NEURONS_LAYERS;
    const int num_neurons_in = NUM_NEURONS_INPUT;
    const int num_neurons_hidden = NUM_NEURONS_HIDDEN;
    const int num_neurons_out = NUM_NEURONS_OUTPUT;

    // Vector of number of neurons in layer_in, layer_H1, layer_H2, ..., layer_Hd, layer_out;
    const int topology[num_neuron_layers] = {num_neurons_in, num_neurons_hidden, num_neurons_out};


    const bool clamp_biases  = false;
    const bool clamp_weights = false;

    const bool statistics        = STATISTICS;
    const bool writeLaTeX_result = WRITELATEX;

    const int threshold_biases  = THRESHOLD_WEIGHTS;
    const int threshold_weights = THRESHOLD_WEIGHTS;
    const int threshold_scores  = THRESHOLD_SCORE;

    // Program the wheel to value(s) after Bootstrapping
    // const Torus32 mu_boot = modSwitchToTorus32(1, space_after_bs);

    const int total_num_hidden_neurons = n_images * NUM_NEURONS_HIDDEN;  //TODO (sum all num_neurons_hidden)*n_images
    const double avg_bs  = 1./NUM_NEURONS_HIDDEN;
    const double avg_total_bs  = 1./total_num_hidden_neurons;
    const double avg_img = 1./n_images;
    const double clocks2seconds = 1. / CLOCKS_PER_SEC;

    // Huge arrays
    int*** weights = new int**[num_wire_layers];  // allocate and fill matrices holding the weights
    NativeInteger*** weights_1 = new NativeInteger**[num_wire_layers];
    int ** biases  = new int* [num_wire_layers];  // allocate and fill vectors holding the biases
    int ** images  = new int* [n_images];
    int  * labels  = new int  [n_images];

    // Temporary variables
    string line;
    int el, l;
    int num_neurons_current_layer_in, num_neurons_current_layer_out;

    //! binfhecontext strat
    auto cc = CryptoContextImpl<DCRTPoly>();

    bool test_BF = false;

    int p = 512;

    cc.Generate_Default_params();
    int q = cc.HESea_GetParams()->GetLWEParams()->Getq().ConvertToInt();


    // Sample Program: Step 2: Key Generation
    // Generate the secret key
    auto sk = cc.HESea_KeyGen02();

    std::cout << "Generating the bootstrapping keys..." << std::endl;

    // Generate the bootstrapping keys (refresh and switching keys)
    cc.HESea_BTKeyGen(sk);

    std::cout << "Completed the key generation." << std::endl;


    if(test_BF)
    {
        for(int i=0;i<p/2+5;i++)
        {
            int x = 256;
            LWECiphertext temp = cc.HESea_Encrypt(sk, x, p);
            auto ct_sign = cc.HESea_MyEvalSigndFunc(temp, p);
            LWEPlaintext tempp;
            cc.HESea_Decrypt(sk, ct_sign, &tempp, p);
            cout<<"input and output after BF are "<<x<<"    "<<tempp<<endl;
        }
    }

    if (VERBOSE) cout << "IMPORT PIXELS, WEIGHTS, BIASES, and LABELS FROM FILES" << endl;
    if (VERBOSE) cout << "Reading images (regardless of dimension) from " << FILE_TXT_IMG << endl;
    ifstream file_images(FILE_TXT_IMG);

    for (int img=0; img<n_images; ++img)
        images[img] = new int[num_neurons_in];

    int filling_image = 0;
    int image_count = 0;
    while(getline(file_images, line))
    {
        images[filling_image][image_count++] = stoi(line);
        if (image_count == num_neurons_in)
        {
            image_count = 0;
            filling_image++;
        }
        if (filling_image>=n_images) break;
    }
    file_images.close();


    if (VERBOSE) cout << "Reading weights from " << FILE_TXT_WEIGHTS << endl;
    ifstream file_weights(FILE_TXT_WEIGHTS);

    num_neurons_current_layer_out = topology[0];
    for (l=0; l<num_wire_layers; ++l)
    {
        num_neurons_current_layer_in = num_neurons_current_layer_out;
        num_neurons_current_layer_out = topology[l+1];

        weights[l] = new int*[num_neurons_current_layer_in];
        weights_1[l] = new NativeInteger*[num_neurons_current_layer_in];
        for (int i = 0; i<num_neurons_current_layer_in; ++i)
        {
            weights[l][i] = new int[num_neurons_current_layer_out];
            weights_1[l][i] = new NativeInteger[num_neurons_current_layer_out];
            for (int j=0; j<num_neurons_current_layer_out; ++j)
            {
                getline(file_weights, line);
                el = stoi(line);
                if (clamp_weights)
                {
                    if (el < -threshold_weights)
                        el = -threshold_weights;
                    else if (el > threshold_weights)
                        el = threshold_weights;
                    // else, nothing as it holds that: -threshold_weights < el < threshold_weights
                }
                weights[l][i][j] = el;
                // NativeInteger a = NativeInteger((el+p)%p);
                weights_1[l][i][j] = NativeInteger((el+q)%q);
            }
        }
    }
    file_weights.close();


    if (VERBOSE) cout << "Reading biases from " << FILE_TXT_BIASES << endl;
    ifstream file_biases(FILE_TXT_BIASES);

    num_neurons_current_layer_out = topology[0];
    for (l=0; l<num_wire_layers; ++l)
    {
        num_neurons_current_layer_in = num_neurons_current_layer_out;
        num_neurons_current_layer_out = topology[l+1];

        biases [l] = new int [num_neurons_current_layer_out];
        for (int j=0; j<num_neurons_current_layer_out; ++j)
        {
            getline(file_biases, line);
            el = stoi(line);
            if (clamp_biases)
            {
                if (el < -threshold_biases)
                    el = -threshold_biases;
                else if (el > threshold_biases)
                    el = threshold_biases;
                // else, nothing as it holds that: -threshold_biases < el < threshold_biases
            }
            biases[l][j] = el;
        }
    }
    file_biases.close();


    if (VERBOSE) cout << "Reading labels from " << FILE_TXT_LABELS << endl;
    ifstream file_labels(FILE_TXT_LABELS);
    for (int img=0; img<n_images; ++img)
    {
        getline(file_labels, line);
        labels[img] = stoi(line);
    }
    file_labels.close();

    if (VERBOSE) cout << "Import done. END OF IMPORT" << endl;


    int** weight_layer;
    int * bias;
    int * image;
    int pixel, label;
    int x, w, w0;


    NativeInteger w_1;
    vector<LWECiphertext> enc_imgae_1;
    vector<LWECiphertext> multi_sum_1;
    vector<LWECiphertext> bootstrapped_1;



    int multi_sum_clear[num_neurons_hidden];
    int output_clear   [num_neurons_out];

    int max_score = 0;
    int max_score_clear = 0;
    int class_enc = 0;
    int class_clear = 0;
    int score = 0;
    LWEPlaintext score_1;
    int score_clear = 0;


    bool failed_bs = false;
    // Counters
    int count_errors = 0;
    int count_errors_with_failed_bs = 0;
    int count_disagreements = 0;
    int count_disagreements_with_failed_bs = 0;
    int count_disag_pro_clear = 0;
    int count_disag_pro_hom = 0;
    int count_wrong_bs = 0;

    int r_count_errors, r_count_disagreements, r_count_disag_pro_clear, r_count_disag_pro_hom, r_count_wrong_bs, r_count_errors_with_failed_bs, r_count_disagreements_with_failed_bs;
    double r_total_time_network, r_total_time_bootstrappings;

    // For statistics output
    double avg_time_per_classification = 0.0;
    double avg_time_per_bootstrapping = 0.0;
    double total_time_bootstrappings = 0.0;
    double total_time_network = 0.0;
    double error_rel_percent = 0.0;

    // Timings
    clock_t bs_begin, bs_end, net_begin, net_end;
    double time_per_classification, time_per_bootstrapping, time_bootstrappings;

    time_t begin, end;
    begin = time(NULL);

    pid_t pids[N_PROC];
    int pipes[N_PROC][2];

    for (int id_proc=0; id_proc < N_PROC; ++id_proc)
    {
        pipe(pipes[id_proc]);   // before fork!
        pid_t pid = fork();
        if (pid != 0)
        {
            pids [id_proc] = pid;
            close(pipes[id_proc][1]);
        }
        else
        {
            close(pipes[id_proc][0]);
            for (int img = id_proc*slice; img < ( (id_proc+1)*slice) && (img< n_images); /*img*/ )
            {
                image = images[img];
                label = labels[img];
                ++img;

                // Generate encrypted inputs for NN (LWE samples for each image's pixels on the fly)
                // To be generic...
                num_neurons_current_layer_out= topology[0];
                num_neurons_current_layer_in = num_neurons_current_layer_out;

                for (int i = 0; i < num_neurons_current_layer_in; ++i)
                {
                    pixel = image[i];
                    if (noisyLWE)
                    {
                        //! Encryt message with modulus p
                        auto ct = cc.HESea_Encrypt(sk, (pixel+p) % p, p);
                        enc_imgae_1.push_back(ct);
                    }
                    else
                    {
                        //! Encrypt message without noise
                        cc.HESea_TraivlEncrypt((pixel+p) % p, p);
                    }
                }

                // ========  FIRST LAYER(S)  ========
                net_begin = clock();

                for (l=0; l<num_wire_layers - 1 ; ++l)     // Note: num_wire_layers - 1 iterations; last one is special. Access weights from level l to l+1.
                {
                    // To be generic...
                    num_neurons_current_layer_in = num_neurons_current_layer_out;
                    num_neurons_current_layer_out= topology[l+1];
                    bias = biases[l];
                    weight_layer = weights[l];
                    for (int j=0; j<num_neurons_current_layer_out; ++j)
                    {
                        w0 = bias[j];
                        multi_sum_clear[j] = w0;
                        auto ct = cc.HESea_TraivlEncrypt((w0 + p) % p, p);
                        multi_sum_1.push_back(ct);
                        for (int i=0; i<num_neurons_current_layer_in; ++i)
                        {
                            //! compute in plaintext
                            x = image [i];  // clear input
                            w = weight_layer[i][j];  // w^dagger
                            multi_sum_clear[j] += x * w; // process clear input

                            //! compute in ciphertext
                            w_1 = weights_1[l][i][j];
                            const NativeVector temp_A = enc_imgae_1[i]->GetA().ModMul(w_1);
                            auto temp_B = enc_imgae_1[i]->GetB().ModMul(w_1, q);
                            multi_sum_1[j]->SetA(temp_A.ModAdd(multi_sum_1[j]->GetA()));
                            multi_sum_1[j]->SetB(temp_B.ModAdd(multi_sum_1[j]->GetB(), q));
                        }
                    }
                }


                    
                // Bootstrap multi_sum
                // bootstrapped = new_LweSample_array(num_neurons_current_layer_out, in_out_params);
                bs_begin = clock();
                for (int j=0; j<num_neurons_current_layer_out; ++j)
                {
                    //! signfunc by our method
                    auto ct_sign = cc.HESea_MyEvalSigndFunc(multi_sum_1[j], p);
                    bootstrapped_1.push_back(ct_sign);
                    if(test_BF){
                        LWEPlaintext temp,temp1;
                        cc.HESea_Decrypt(sk, ct_sign, &temp, p);
                        cc.HESea_Decrypt(sk, multi_sum_1[j], &temp1, p);
                        temp = (temp<p/2)? temp:temp-p;
                        temp1 = (temp1<p/2)? temp1:temp1-p;
                        if (temp*multi_sum_clear[j] <= 0 || true){
                            cout<<"True value before bootstrapping is "<<multi_sum_clear[j]<< "   " ;
                            cout<<temp1<<"                ";
                            cout<<temp<<endl;
                        } 
                    }

                }
                bs_end = clock();
                time_bootstrappings = bs_end - bs_begin;
                // cout<< time_bootstrappings;
                total_time_bootstrappings += time_bootstrappings;
                time_per_bootstrapping = time_bootstrappings*avg_bs;
                // if (VERBOSE) cout <<  time_per_bootstrapping*clocks2seconds << " [sec/bootstrapping]" << endl;

                //! clear the vector mult_sum_1 to compute the next layer 
                multi_sum_1.clear();
                // ========  LAST (SECOND) LAYER  ========
                max_score = threshold_scores;
                max_score_clear = threshold_scores;

                bias = biases[l];
                weight_layer = weights[l];
                l++;
                num_neurons_current_layer_in = num_neurons_current_layer_out;
                num_neurons_current_layer_out= topology[l]; // l == L = 2

                for (int j=0; j<num_neurons_current_layer_out; ++j)
                {
                    w0 = bias[j];
                    output_clear[j] = w0;
                    auto ct = cc.HESea_TraivlEncrypt((w0 + p) % p, p);
                    multi_sum_1.push_back(ct);                 

                    for (int i=0; i<num_neurons_current_layer_in; ++i)
                    {
                        w = weight_layer[i][j];
                        w_1 = weights_1[l-1][i][j]; 

                        // process the encrypted data 
                        auto temp_A = bootstrapped_1[i]->GetA().ModMul(w_1);
                        auto temp_B = bootstrapped_1[i]->GetB().ModMulFast(w_1, bootstrapped_1[i]->GetA().GetModulus());
                        multi_sum_1[j]->SetA(temp_A.ModAdd(multi_sum_1[j]->GetA()));
                        multi_sum_1[j]->SetB(temp_B.ModAdd(multi_sum_1[j]->GetB(), q));

                        // process clear input
                        if (multi_sum_clear[i] < 0)
                            output_clear[j] -= w;
                        else
                            output_clear[j] += w;
                    }

                    //! Decrypt here 
                    cc.HESea_Decrypt(sk, multi_sum_1[j], &score_1, p);
                    score_1 = (score_1>p/2)? score_1%p-p: score_1%p;
                    if (score_1 > max_score)
                    {
                        max_score = score_1;
                        class_enc = j;
                    }
                    score_clear = output_clear[j];
                    if (score_clear > max_score_clear)
                    {
                        max_score_clear = score_clear;
                        class_clear = j;
                    }
                }
                            
                if (class_enc != label)
                {
                    count_errors++;
                    if (failed_bs)
                        count_errors_with_failed_bs++;
                }

                if (class_clear != class_enc)
                {
                    count_disagreements++;
                    if (failed_bs)
                        count_disagreements_with_failed_bs++;

                    if (class_clear == label)
                        count_disag_pro_clear++;
                    else if (class_enc == label)
                        count_disag_pro_hom++;
                }
                net_end = clock();
                time_per_classification = net_end - net_begin;
                total_time_network += time_per_classification;
                // if (VERBOSE) cout << "            "<< time_per_classification*clocks2seconds <<" [sec/classification]" << endl;

                enc_imgae_1.clear();
                bootstrapped_1.clear();
                multi_sum_1.clear();

                cout<<"Process "<<id_proc<<"  image "<< img <<" output the result :"<<"\n";
                cout<<"the label of digit is "<<label<<endl;
                cout<<"the recognition result without fhe is "<< class_clear<<endl;
                cout<<"the recognition result using fhe is "<<class_enc<<endl;
                cout<<"-----------------------------------------------------------------------------------------"<<endl;        

            }
            // for (int img = id_proc*slice; img < ( (id_proc+1)*slice) && (img< n_images); /*img*/ )
            FILE* stream = fdopen(pipes[id_proc][1], "w");
            fprintf(stream, "%d,%d,%d,%d,%d,%d,%d,%lf,%lf\n", count_errors, count_disagreements, count_disag_pro_clear, count_disag_pro_hom, count_wrong_bs,
                    count_errors_with_failed_bs, count_disagreements_with_failed_bs, total_time_network, total_time_bootstrappings);
            fclose(stream);
            exit(0);
        }
    }

    for (auto pid : pids)
    {
        waitpid(pid, 0, 0);
    }

    end = time(NULL);
    double total_time = (end - begin);
    // double avg_time = (total_time*clocks2seconds)/n_images; 


    time_per_classification = 0.0;
    time_per_bootstrapping = 0.0;
    for (int id_proc=0; id_proc<N_PROC; ++id_proc)
    {
        FILE* stream = fdopen(pipes[id_proc][0], "r");
        fscanf(stream, "%d,%d,%d,%d,%d,%d,%d,%lf,%lf\n", &r_count_errors, &r_count_disagreements,
               &r_count_disag_pro_clear, &r_count_disag_pro_hom, &r_count_wrong_bs, &r_count_errors_with_failed_bs,
               &r_count_disagreements_with_failed_bs, &r_total_time_network, &r_total_time_bootstrappings);
        fclose(stream);
        count_errors += r_count_errors;
        count_disagreements += r_count_disagreements;
        count_disag_pro_clear += r_count_disag_pro_clear;
        count_disag_pro_hom += r_count_disag_pro_hom;
        count_wrong_bs += r_count_wrong_bs;
        count_errors_with_failed_bs += r_count_errors_with_failed_bs;
        count_disagreements_with_failed_bs += r_count_disagreements_with_failed_bs;
        time_per_classification += r_total_time_network;
        time_per_bootstrapping += r_total_time_bootstrappings;
    }



    if (statistics)
    {
        ofstream of(FILE_STATISTICS);
        // Print some statistics
        error_rel_percent = count_errors*avg_img*100;
        avg_time_per_classification = time_per_classification*avg_img*clocks2seconds;
        avg_time_per_bootstrapping  = time_per_bootstrapping *avg_total_bs *clocks2seconds;

        cout<<"The recognition process is completed, total "<<n_images<<"digits have been recogized "<<endl;
        cout << "Recognition errors: " << count_errors << " / " << n_images << " (" << error_rel_percent << " %)" << endl;
        cout << "Disagreements: " << count_disagreements<<endl;
        // cout << " (pro-clear/pro-hom: " << count_disag_pro_clear << " / " << count_disag_pro_hom << ")" << endl;
        // cout << "Wrong bootstrappings: " << count_wrong_bs << endl;
        // cout << "Errors with failed bootstrapping: " << count_errors_with_failed_bs << endl;
        // cout << "Disagreements with failed bootstrapping: " << count_disagreements_with_failed_bs << endl;
        cout << "Average time for the evaluation of each digit (seconds): " << total_time/n_images << endl;
        // cout<<"total CPU time is "<<total_time<<"   "<<begin<<"        "<<end<<endl;
        // cout << "Avg. time per bootstrapping (seconds): " << avg_time << endl;

        // of << "Errors: " << count_errors << " / " << n_images << " (" << error_rel_percent << " %)" << endl;
        // of << "Disagreements: " << count_disagreements;
        // of << " (pro-clear/pro-hom: " << count_disag_pro_clear << " / " << count_disag_pro_hom << ")" << endl;
        // of << "Wrong bootstrappings: " << count_wrong_bs << endl;
        // of << "Errors with failed bootstrapping: " << count_errors_with_failed_bs << endl;
        // of << "Disagreements with failed bootstrapping: " << count_disagreements_with_failed_bs << endl;
        // of << "Avg. time for the evaluation of the network (seconds): " << avg_time_per_classification << endl;
        // of << "Avg. time per bootstrapping (seconds): " << avg_time_per_bootstrapping << endl;

        // Write some statistics
        cout << "\n Wrote statistics to file: " << FILE_STATISTICS << endl << endl;
        of.close();
    }

    if (writeLaTeX_result)
    {
        cout << "\n Wrote LaTeX_result to file: " << FILE_LATEX << endl << endl;
        ofstream of(FILE_LATEX);
        of << "%\\input{"<<FILE_LATEX<<"}" << endl;

        of << "% Experiments detailed" << endl;
        of << "\\newcommand{\\EXPnumBS}{$"<<total_num_hidden_neurons<<"$}" << endl;
        of << "\\newcommand{\\EXPbsEXACT}{$"    <<avg_time_per_bootstrapping<<"$\\ [sec/bootstrapping]}" << endl;
        of << "\\newcommand{\\EXPtimeEXACT}{$"  <<avg_time_per_classification<<"$\\ [sec/classification]}" << endl;

        of << "\\newcommand{\\EXPnumERRabs}{$"  <<count_errors<<"$}" << endl;
        of << "\\newcommand{\\EXPnumERRper}{$"  <<error_rel_percent<<"\\ \\%$}" << endl;
        of << "\\newcommand{\\EXPwrongBSabs}{$" <<count_wrong_bs<<"$}" << endl;
        of << "\\newcommand{\\EXPwrongDISabs}{$"<<count_disagreements_with_failed_bs<<"$}" << endl;
        of << "\\newcommand{\\EXPdis}{$"        <<count_disagreements<<"$}" << endl;
        of << "\\newcommand{\\EXPclear}{$"      <<count_disag_pro_clear<<"$}" << endl;
        of << "\\newcommand{\\EXPhom}{$"        <<count_disag_pro_hom<<"$}" << endl << endl;

        of << "\\begin{Verbatim}[frame=single,numbers=left,commandchars=+\\[\\]%" << endl;
        of << "]" << endl;
        of << "### Classified samples: +EXPtestset" << endl;
        of << "Time per bootstrapping: +EXPbsEXACT" << endl;
        of << "Errors: +EXPnumERRabs / +EXPtestset (+EXPnumERRper)" << endl;
        of << "Disagreements: +EXPdis" << endl;
        of << "(pro-clear/pro-hom: +EXPclear / +EXPhom)" << endl;
        of << "Wrong bootstrappings: +EXPwrongBSabs" << endl;
        of << "Disagreements with wrong bootstrapping: +EXPwrongDISabs" << endl;
        of << "Avg. time for the evaluation of the network: +EXPtimeEXACT" << endl;
        of << "\\end{Verbatim}" << endl;
        of.close();
    }

    // free memory
    // delete_gate_bootstrapping_secret_keyset(secret);
    // delete_gate_bootstrapping_parameters(params);

    deleteTensor(weights,num_wire_layers, topology);
    deleteMatrix(biases, num_wire_layers);
    deleteMatrix(images, n_images);
    delete[] labels;

    return 0;

}



void deleteTensor(int*** tensor, int dim_tensor, const int* dim_vec)
{
    int** matrix;
    int dim_mat;
    for (int i=0; i<dim_tensor; ++i)
    {
        matrix =  tensor[i];
        dim_mat = dim_vec[i];
        deleteMatrix(matrix, dim_mat);
    }
    delete[] tensor;
}


void deleteMatrix(int** matrix, int dim_mat)
{
    for (int i=0; i<dim_mat; ++i)
    {
        delete[] matrix[i];
    }
    delete[] matrix;
}


