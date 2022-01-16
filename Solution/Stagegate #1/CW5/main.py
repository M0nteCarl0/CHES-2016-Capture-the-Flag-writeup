import chipwhisperer as cw
import chipwhisperer.analyzer as cwa
import matplotlib.pyplot as plt
import matplotlib as mpl
import datetime
import chipwhisperer as cw
import numpy as np

import binascii

from tqdm import tqdm
from chipwhisperer.analyzer.attacks.cpa import CPA
from chipwhisperer.analyzer.attacks.cpa_algorithms.progressive import CPAProgressive
from chipwhisperer.analyzer.attacks.models.DES import DES, SBox_output, SBox_input
from chipwhisperer.analyzer.attacks.models.AES128_8bit import AES128_8bit, SBox_output

def cw42cwp5(path2traces):
    project = cw.open_project(path2traces)
    proj = cw.create_project("Traces_CTF1", overwrite=True)
    print("begin conversion")
    for i in range(len(project.waves)):
        print(binascii.hexlify(project.textins[i]))
        print(binascii.hexlify(project.textouts[i]))
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

    leak_model = AES128_8bit(SBox_output)
    attack = cwa.cpa(project, leak_model)
    attack.set_analysis_algorithm(CPAProgressive, leak_model)
    attack.set_trace_start(0)
    attack.set_traces_per_attack(-1)
    attack.set_iterations(10)
    attack.set_reporting_interval(3)
    attack.set_target_subkeys([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
    attack.set_point_range((0, 9996))


    print(attack)
    results = attack.run(callback)
    print(results)

    


if __name__ == '__main__':
    #cw42cwp5('secretfixed_rand_P57.cwp')
    cpa_aes128ecb_on_Stagegate1('Traces_CTF1.cwp')
   