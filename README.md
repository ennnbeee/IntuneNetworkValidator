# 📲 IntuneNetworkValidator

The IntuneNetworkValidator script is a PowerShell tool designed to allow for automatic testing of Intune Network Endpoints.

## ⚠ Public Preview Notice

IntuneNetworkValidator is currently in Public Preview, meaning that although the it is functional, you may encounter issues or bugs with the script.

> [!TIP]
> If you do encounter bugs, want to contribute, submit feedback or suggestions, please create an issue.

## 🌟 Features

You can run the script to test different Intune Network Endpoints, regions, and carry out a lite or full validation of IP Address ranges. By default the script will test all scopes, regions, and a limited set of IP addresses within the full ranges available.

- Use **testScope** to specify the scope of the test, selections from: 'Autopilot', 'Apple', 'Android', 'W365', 'W365-Client', 'W365-CloudPC', and 'All' (Default)
- Use **testType** to specify whether an individual IP address in a range is tested, or full range is tested.
- Use **region** to test the global and specific region Intune Network Endpoints from: 'North America', 'Europe', 'Australia', and 'Asia Pacific'

## 🗒 Prerequisites

> [!IMPORTANT]
>
> - Supports PowerShell 5 and 7 on Windows

## 🔄 Updates

- **v0.1.6**
  - Initial release

## ⏯ Usage

Running the script without any parameters will perform a Lite test for all Intune Network Endpoints for all regionds:

```PowerShell
.\IntuneNetworkValidator.ps1
```

Running the script with the parameter below will test the [Apple Network Endpoints](https://support.apple.com/HT210060)

```PowerShell
.\IntuneNetworkValidator.ps1 -testScope Apple
```

Running the script with the parameter below will test the [Android Enterprise Network Endpoints](https://support.google.com/work/android/answer/10513641?hl=en)

```PowerShell
.\IntuneNetworkValidator.ps1 -testScope Android
```

Running the script with the parameters below will test the [Windows Autopilot Network Endpoints](https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/intune-endpoints) for Global and Europe.

```PowerShell
.\IntuneNetworkValidator.ps1 -testScope Autopilot -region Europe
```

## 🎬 Demos

TBA

## 🚑 Support

If you encounter any issues or have questions:

1. Check the [Issues](https://github.com/ennnbeee/IntuneNetworkValidator/issues) page
2. Open a new issue if needed

- 📝 [Submit Feedback](https://github.com/ennnbeee/IntuneNetworkValidator/issues/new?labels=feedback)
- 🐛 [Report Bugs](https://github.com/ennnbeee/IntuneNetworkValidator/issues/new?labels=bug)
- 💡 [Request Features](https://github.com/ennnbeee/IntuneNetworkValidator/issues/new?labels=enhancement)

Thank you for your support.

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

Created by [Nick Benton](https://github.com/ennnbeee) of [odds+endpoints](https://www.oddsandendpoints.co.uk/)
