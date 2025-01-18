# SimpleHypervisor

## Overview

**SimpleHypervisor** is a lightweight hypervisor developed for educational and research purposes. The project leverages hardware virtualization features to provide fundamental virtualization capabilities, making it an excellent resource for those interested in hypervisor development, low-level programming, and virtualization technology.

## Features

- **Support for Multiple CPU Cores**: The hypervisor is designed to work seamlessly across multiple CPU cores, allowing for efficient virtualization in multi-core environments.
- **Extended Page Tables (EPT)**: EPT support enables efficient memory virtualization by leveraging Intel’s hardware-assisted virtualization features.
- **VM-Exit Handling**: Handles critical VMExit events such as CPUID, MSR access, and more, ensuring smooth interaction between the guest and the hypervisor.

## Getting Started

### Prerequisites

- **Hardware Requirements**:
  - A processor with Intel VT-x support.
  - BIOS/UEFI with virtualization enabled.
  
- **Software Requirements**:
  - Windows operating system.
  - Windows Driver Kit (WDK) for driver development.
  - Visual Studio with C++ development tools.

### Cloning the Repository

```bash
git clone https://github.com/un4ckn0wl3z/SimpleHypervisor.git
cd SimpleHypervisor
```

### Building the Project

1. Open the solution file in Visual Studio.
2. Configure the build environment to `Release` or `Debug`.
3. Build the solution to generate the hypervisor driver.

### Running the Hypervisor

1. Load the driver using a tool such as `sc.exe` or a custom loader.
2. Ensure that virtualization is enabled in your system BIOS/UEFI.
3. Check the logs to verify that the hypervisor is operational.

## Architecture

### Multi-Core Support
The hypervisor initializes and manages virtualization on all available CPU cores, utilizing processor-specific VMCS (Virtual Machine Control Structure) for each core.

### Extended Page Tables (EPT)
EPT allows the hypervisor to provide efficient memory translation and isolation for the guest OS. This feature enables:
- Faster memory access.
- Simplified management of guest memory.

### VMExit Handling
The hypervisor captures and processes specific VMExit events, including but not limited to:
- **CPUID**: Modify or restrict guest CPUID instructions.
- **MSR Access**: Monitor and handle guest Model-Specific Registers (MSRs).
- **Control Register Access**: Intercept changes to control registers (e.g., CR0, CR3).

## Credits

This project was inspired by and builds upon the work of:
- **扑克王 (I Love Code)**: [http://www.woaidaima.com](http://www.woaidaima.com ) / **[I Love Code's 51CTO]**: [edu.51cto.com](https://edu.51cto.com/course/14417.html)
- **NewBluePill_深入理解硬件虚拟机** by 于淼 and 戚正伟 (2011)

## Disclaimer

This project is for educational and research purposes only. The author is not responsible for any misuse or damage caused by the use of this software.

## Contact

- **GitHub**: [@un4ckn0wl3z](https://github.com/un4ckn0wl3z)

Feel free to reach out with questions or feedback!

