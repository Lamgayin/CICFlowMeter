# 改進的地方
# 本專案基於上位作者的改版進行了修改，以實現自己所需要的功能。下面是修改地方。
- 1.可在後台運行（無ui）Cicflowmeter
- 2.將生成的流量傳輸到一個指定的地址。

### Fixed version of the CICFlowMeter tool

As part of our [WTMC 2021 paper](https://downloads.distrinet-research.be/WTMC2021/Resources/wtmc2021_Engelen_Troubleshooting.pdf), we analysed and improved the CICFlowMeter tool, the result of 
which can be found in this repository. If you use this improved CICFlowMeter tool, please cite our paper:

            @inproceedings{engelen2021troubleshooting,
            title={Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study},
            author={Engelen, Gints and Rimmer, Vera and Joosen, Wouter},
            booktitle={2021 IEEE Security and Privacy Workshops (SPW)},
            pages={7--12},
            year={2021},
            organization={IEEE}
            }

A detailed list of all fixes and improvements, as well as implications of the changes can be found on [our webpage](https://downloads.distrinet-research.be/WTMC2021/),
which hosts the extended documentation of our paper. 

Here we stick to a brief summary of all changes to the CICFlowMeter tool: 

- A TCP flow is no longer terminated after a single FIN packet. It now terminates after mutual exchange of 
FIN packets, which is more in line with the TCP specification.
  
- An RST packet is no longer ignored. Instead, the RST packet also terminates a TCP flow.

- The Flow Active and Idle time features no longer encode an absolute timestamp.

- The values for *Fwd PSH Flags*, *Bwd PSH Flags*, *Fwd URG Flags* and *Bwd URG Flags* are now correctly incremented.

### Running the tool

To run the tool, please refer to the [original CICFlowMeter repository](https://github.com/ahlashkari/CICFlowMeter) for instructions.

