# Примеры использования eUPF
eUPF может быть использован в различных сценариях совместо с несколькими проектами, реализующими ядро 5G сети.

eUPF использует функционал марщрутиации хоста, на котором запущен. Поскольку eUPF не выполняет функции натирования(NAT), то при необходимости использования трансляции адресов потребуется внешний модуль NAT.

## Развертывания с использованием Docker-compose

| Ядро 5G | Радиосеть(эмулятор) | Опции | Описание |
| ------- | --- | ------- | ---------------------- |
| Open5GS | UERANSIM | - | [Open5GS](https://github.com/edgecomllc/open5gs-compose) |
| Open5GS | OpenAirInterface | - | В работе... |
| Free5GC | UERANSIM | - | [Free5GC](https://github.com/edgecomllc/free5gc-compose/blob/master/README.md) |
| Free5GC | UERANSIM | ULCL | [Free5GC с поддержкой опции UpLink Classifier с eUPF в качестве I-UPF](https://github.com/edgecomllc/free5gc-compose/tree/ulcl-n9upf-experimetns#ulcl-configuration) |
| OpenAirInterface 5G Core | OpenAirInterface 5G RAN	 | - | [OAI в режиме 5G SA с использованием L2 nFAPI симулятора](./oai-nfapi-sim-compose/README.md) |

## Резвертывания с использованием K8s

При использовании K8s для организации роутинга трафика в сторону абонентов используется BGP для анонсирования абонентских подсетей в сторону Kubernetes нода.

| 5G Core | RAN | Options | Deployment description |
| ------- | --- | ------- | ---------------------- |
| Open5GS | UERANSIM | Calico BGP | [Open5GS & Calico BGP](./open5gs-with-bgp/README.md) |
| Open5GS | UERANSIM | Calico BGP with Slices | [Open5GS & Calico BGP с использованием слайсинга](./open5gs-with-bgp-and-slices/README.md) |
| Open5GS | UERANSIM | Load Balanced eUPF | [Open5GS & балансировка нагрузки между несколькими eUPF](./open5gs-with-scaling-eupf/README.md) |
| Open5GS | srsRAN | Calico BGP | [Open5GS & srsRAN & Calico BGP](./srsran-gnb/README.md) |
| Free5GC | UERANSIM | Calico BGP | [Free5GC & Calico BGP](./free5gc-with-bgp/README.md) |
| Free5GC | UERANSIM | ULCL | [Free5GC & ULCL](./free5gc-ulcl/README.md) |
| OpenAirInterface 5G Core | OpenAirInterface 5G RAN | - | [OAI](./oai/README.md) |