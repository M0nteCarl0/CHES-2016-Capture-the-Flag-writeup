import chipwhisperer as cw
import chipwhisperer.analyzer as cwa
import matplotlib.pyplot as plt
import matplotlib as mpl
import datetime
import chipwhisperer as cw
import chipwhisperer.analyzer as cwa
import numpy as np

import binascii

from tqdm import tqdm
from chipwhisperer.analyzer.attacks.cpa import CPA
from chipwhisperer.analyzer.attacks.cpa_algorithms.progressive import CPAProgressive
from chipwhisperer.analyzer.attacks.models.DES import DES, SBox_output, SBox_input
from chipwhisperer.analyzer.attacks.models.AES128_8bit import AES128_8bit, SBox_output


def cw42cwp5(path2traces, name_destination = 'Traces_CTF3' ):
    project = cw.open_project(path2traces)
    proj = cw.create_project(name_destination, overwrite=True)
    print("begin conversion")
    for i in range(len(project.waves)):
        print("Text in:")
        print(binascii.hexlify(project.textins[i]))
        print("Text out:")
        print(binascii.hexlify(project.textouts[i]))
        print("Key enc:")
        print(binascii.hexlify(project.keys[i]))

        trace = cw.Trace(project.waves[i], project.textins[i], project.textouts[i],  project.textins[i])
        proj.traces.append(trace)

    proj.save()
    print("End conversion")

def callback():
    print("Atacking trace set ")

def cpa_aes128ecb_on_Stagegate1(path2traces):
    project = cw.open_project(path2traces)
    for i in range(9):
        plt.plot(project.waves[i])
    plt.show()


    resync_traces = cwa.preprocessing.ResyncSAD(project)
    resync_traces.ref_trace = 0
    resync_traces.target_window = (2000, 4000)
    resync_traces.max_shift = 100
    resync_analyzer = resync_traces.preprocess()

    plt.figure()
    for i in range(10):
        plt.plot(resync_analyzer.waves[i])
    plt.show()



    leak_model = AES128_8bit(SBox_output)
    attack = cwa.cpa(resync_analyzer, leak_model)
    attack.set_analysis_algorithm(CPAProgressive, leak_model)
    attack.set_trace_start(0)
    attack.set_traces_per_attack(-1)
    attack.set_iterations(10)
    attack.set_reporting_interval(3)
    attack.set_target_subkeys([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
    attack.set_point_range((1000, 8000))


    print(attack)
    results = attack.run(callback)
    print(results)

    


if __name__ == '__main__':
    #cw42cwp5('secretfixed_rand_P58.cwp','Traces_CTF3')
    #cpa_aes128ecb_on_Stagegate1('Traces_CTF3.cwp')
    #cw42cwp5('knownfixed_rand_P58.cwp', 'Traces_CTF2')
    cpa_aes128ecb_on_Stagegate1('Traces_CTF2.cwp')
   