**Diagward · srv-db01.khachhang.vn**
Dell Inc. PowerEdge R740 · Serial / service tag: `7XK9Q73` · AlmaLinux 9.4 (Seafoam Ocelot) · 2026-10-01 16:00:20 +07:00

### 🔴 CẦN XỬ LÝ NGAY
4 lỗi nghiêm trọng · 3 cảnh báo · 1 lưu ý · đã kiểm tra 8/12 nhóm linh kiện (4 nhóm chỉ một phần)

### Vấn đề phát hiện (8)
1. 🔴 **Ổ /dev/sda sắp hỏng: 24 sector không đọc được**
   - `/dev/sda` · Ổ cứng
   - Thuộc tính S.M.A.R.T. 197 Current_Pending_Sector = 24 và 198 Offline_Uncorrectable = 24. Sector không đọc được nghĩa là dữ liệu trên đó có thể đã mất, và số lượng thường tăng nhanh.
   - **Cách xử lý:** Sao lưu dữ liệu ngay. Thay ổ /dev/sda (serial ZC1234AB). Nếu ổ nằm trong RAID, kiểm tra RAID đã rebuild xong trước khi rút ổ.
2. 🔴 **Ổ /dev/sda không qua bài tự kiểm tra gần nhất**
   - `/dev/sda` · Ổ cứng
   - **Cách xử lý:** Thay ổ.
3. 🔴 **RAID md0 bị suy giảm \[\_U\]: thiếu một ổ thành viên**
   - `md0` · RAID & nhóm lưu trữ
   - /proc/mdstat cho thấy \[2/1] \[\_U]. RAID không còn dự phòng.
   - **Cách xử lý:** Sao lưu ngay, sau đó thay ổ hỏng và thêm lại: mdadm --manage /dev/md0 --add /dev/sdX1
4. 🔴 **Bộ nguồn PSU2 bị hỏng (mất điện đầu vào)**
   - `PSU2` · Nguồn điện
   - **Cách xử lý:** Kiểm tra dây nguồn và PDU cấp cho PSU2; nếu vẫn có điện thì thay PSU2.
5. 🟠 **Thanh RAM DIMM_A1 có lỗi ECC đã sửa (152 lỗi trong 7 ngày)**
   - `DIMM_A1` · Bộ nhớ (RAM)
   - EDAC báo lỗi đã sửa trên một thanh RAM. ECC đã sửa được nhưng đây thường là dấu hiệu trước khi xảy ra lỗi không sửa được.
   - **Cách xử lý:** Lên kế hoạch thay thanh RAM DIMM_A1 trong lần bảo trì tới. Chạy memtester hoặc công cụ chẩn đoán của hãng để xác nhận.
6. 🟠 **Lỗi cáp trên \<script>alert("x")\</script>" onmouseover="alert(1)" '>\<img src=x onerror=alert(2)>**
   - `<script>alert("x")</script>" onmouseover="alert(1)" '><img src=x onerror=alert(2)>` · Ổ cứng
   - UDMA_CRC_Error_Count = 31
   - **Cách xử lý:** Cắm lại hoặc thay cáp SATA/SAS và khe backplane.
7. 🟠 **3 lần khởi động lại bất thường trong 7 ngày**
   - `kernel` · Nhật ký hệ thống
   - ログ: 予期しない再起動 — 服务器意外重启 🔥 (kiểm thử unicode)
   - **Cách xử lý:** Xem nhật ký sự kiện BMC quanh các thời điểm khởi động lại để tìm sự cố nguồn hoặc nhiệt độ.
8. 🔵 **SEL đã đầy 71%**
   - Bộ điều khiển quản trị (BMC)
   - Sự kiện cũ có thể sớm bị ghi đè.

**Đã kiểm tra, ổn:**
- 🟢 3 ổ cứng đạt kiểm tra S.M.A.R.T.
- 🟢 Mọi nhiệt độ đều dưới ngưỡng cảnh báo
- 🟢 6 quạt quay bình thường

### Linh kiện cần thay (dùng khi mở ca bảo hành / RMA)
- 🔴 **Ổ cứng** Seagate ST4000NM0035-1V4107 4.0 TB · Serial: `ZC1234AB` · Vị trí: `/dev/sda (bay 3)`
  - Lý do: Ổ /dev/sda sắp hỏng: 24 sector không đọc được; Ổ /dev/sda không qua bài tự kiểm tra gần nhất
- 🔴 **Bộ nguồn (PSU)** Dell 0PJMDN 750W · Vị trí: `PSU2`
  - Lý do: Bộ nguồn PSU2 bị hỏng (mất điện đầu vào)
- 🟠 **Thanh RAM** Samsung M393A4K40CB2-CVF 32 GiB · Serial: `4C1A2B3D` · Vị trí: `CPU1 DIMM_A1`
  - Lý do: Thanh RAM DIMM_A1 có lỗi ECC đã sửa (152 lỗi trong 7 ngày)

### Chưa kiểm tra đầy đủ
- Thông tin FRU (kiểm tra bị lỗi): ipmitool fru bị quá thời gian: \<script>alert("x")\</script>" onmouseover="alert(1)" '>\<img src=x onerror=alert(2)>
- Card RAID MegaRAID (kiểm tra một phần): Có card RAID nhưng storcli không đọc được pin.
- Nhật ký lỗi NVMe (chưa kiểm tra): Chưa cài nvme.
  - Cài đặt: `dnf install -y nvme-cli`
- Đo tốc độ ổ cứng (chưa kiểm tra): Mặc định tắt vì phải ghi tệp thử.
  - Chạy: `diagward check --bench --bench-dir /var/tmp --bench-mb 1024 --some-very-long-option-name-to-force-wrapping=value`
- Danh sách thanh RAM, hwmon (chưa kiểm tra): Cần quyền root.
  - Chạy với quyền root: `sudo diagward`
- lm-sensors (chưa kiểm tra): Chưa cài sensors.
  - Cài lm_sensors rồi chạy lại Diagward. `sudo dnf install -y lm_sensors`

### Ghi chú
- Diagward chạy không có quyền root nên một số mục đã bị bỏ qua. Hãy chạy lại bằng sudo để có báo cáo đầy đủ.

Diagward 0.1.0-test · https://github.com/nguyenquocanhz/diagward
