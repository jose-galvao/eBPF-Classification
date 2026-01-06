# eBPF-Classification

This repository maintain the codes from the article "Leveraging eBPF/XDP for Real-Time Machine Learning Traffic Classification in 5G User Plane Networks".

Você vai encontrar os diretórios separadas por tipo de classificação: kernel_class e user_class (kernel space e user space classification, respectivamente).

- #### Kernel space

  No diretório kernel_class você vai encontrar três arquivos:
    - *monitorjanela.py*:  É o código responsável pelo espaço de usuário. Ele atua como um gerenciador e faz as seguintes principais funções:
      
      1- Compila e carrega o programa BPF no kernel.
      
      2- Anexa o programa XDP à interface de rede.
      
      3- Preenche o PROG_ARRAY das funções de tail call.
      
      4- Lê o buffer (perf_buffer) e formata os eventos recebidos para exibição no terminal.

  - *monitorjanela.bpf.c*:  É o código responsável pelo espaço do kernel. Suas principais funções são:

    1- Desencapsula os cabeçalhos Ethernet, IP, UDP e GTP-U para acessar o IP interno do usuário.

    2- Calcula a média e variância do Inter-Arrival Time (IAT) dentro de uma janela de 500ms.

    3- Utiliza tail calls para executar as árvores de decisão do modelo (*model500msJANELA.h*).

    4- Envia os resultados da classificação e metadados para o userspace.

  - *model500msJANELA.h*: Este é o arquivo de cabeçalho gerado gerado pelo emlearn que contém a estrutura das árvores de decisão e as funções de predição utilizadas pelo código C.

- #### User space
  
  No diretório user_class você vai encontrar três arquivos:
    - *monitorjanela.py*:  É o código responsável pelo espaço de usuário. Ele atua como um gerenciador e faz as seguintes principais funções:
      
      1- Compila e carrega o programa BPF no kernel.
      
      2- Anexa o programa XDP à interface de rede.
      
      3- Preenche o PROG_ARRAY das funções de tail call.
      
      4- Lê o buffer (perf_buffer) e formata os eventos recebidos para exibição no terminal.

  - *monitorjanela.bpf.c*:  É o código responsável pelo espaço do kernel. Suas principais funções são:

    1- Desencapsula os cabeçalhos Ethernet, IP, UDP e GTP-U para acessar o IP interno do usuário.

    2- Calcula a média e variância do Inter-Arrival Time (IAT) dentro de uma janela de 500ms.

    3- Utiliza tail calls para executar as árvores de decisão do modelo (*model500msJANELA.h*).

    4- Envia os resultados da classificação e metadados para o userspace.

  - *model500msJANELA.h*: Este é o arquivo de cabeçalho gerado gerado pelo emlearn que contém a estrutura das árvores de decisão e as funções de predição utilizadas pelo código C.
