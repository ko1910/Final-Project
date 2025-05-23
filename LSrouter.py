import json
import heapq
import logging

from router import Router
from packet import Packet

class LSrouter(Router):
    """Trien khai giao thuc dinh tuyen trang thai lien ket."""

    def __init__(self, addr, heartbeat_time):
        # Khoi tao router voi dia chi va thoi gian heartbeat
        Router.__init__(self, addr)
        self.heartbeat_time = heartbeat_time
        self.last_time = 0
        self.ls_db = {addr: [0, {}]}
        self.forwarding_table = {}
        self.neighbors = {}
        self.neighbor_costs = {}
        self.seq_num = 0

        self.logger = logging.getLogger(f"LSrouter_{addr}")
        self.logger.setLevel(logging.INFO)
        file_handler = logging.FileHandler(f"lsrouter_{addr}.log", mode='w', encoding='utf-8')
        formatter = logging.Formatter('[%(asctime)s] [%(name)s] %(message)s')
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        self.logger.info(f"Khoi tao router {addr} voi heartbeat_time {heartbeat_time} ms")

    def handle_packet(self, port, packet):
        # Xu ly goi tin den tu cong port
        self.logger.info(f"Nhan goi tin tren cong {port} tu {packet.src_addr} (dich: {packet.dst_addr}, la traceroute: {packet.is_traceroute})")
        if packet.is_traceroute:
            dst = packet.dst_addr
            if dst in self.forwarding_table:
                next_hop, cost = self.forwarding_table[dst]
                for neighbor_port, neighbor_addr in self.neighbors.items():
                    if neighbor_addr == next_hop:
                        self.logger.info(f"Chuyen tiep goi tin du lieu den {dst} qua cong {neighbor_port} (buoc nhay tiep theo: {next_hop}, chi phi: {cost})")
                        self.send(neighbor_port, packet)
                        break
            else:
                self.logger.info(f"Khong co tuyen den dich {dst}, huy goi tin")
        else:
            try:
                lsp = json.loads(packet.content)
                src = packet.src_addr
                seq_num = lsp['seq_num']
                links = lsp['links']
                self.logger.info(f"Xu ly goi tin trang thai lien ket tu {src} voi so thu tu {seq_num}, lien ket: {links}")
            except (json.JSONDecodeError, KeyError) as e:
                self.logger.info(f"Goi tin trang thai lien ket khong hop le tu {packet.src_addr}: {str(e)}")
                return

            if src not in self.ls_db or seq_num > self.ls_db[src][0]:
                self.logger.info(f"Cap nhat co so du lieu trang thai lien ket cho {src} voi so thu tu {seq_num}, lien ket: {links}")
                self.ls_db[src] = [seq_num, links]
                for neighbor_port, neighbor_addr in self.neighbors.items():
                    if neighbor_addr != src:
                        self.logger.info(f"Chuyen tiep goi tin trang thai lien ket tu {src} den {neighbor_addr} qua cong {neighbor_port}")
                        self.send(neighbor_port, packet)
                self._compute_forwarding_table()
            else:
                self.logger.info(f"Bo qua goi tin trang thai lien ket cu/het han tu {src} voi so thu tu {seq_num}")

    def handle_new_link(self, port, endpoint, cost):
        # Xu ly lien ket moi duoc them vao router
        self.logger.info(f"Them lien ket moi: cong {port} den {endpoint} voi chi phi {cost}")
        self.neighbors[port] = endpoint
        self.neighbor_costs[endpoint] = cost
        self.ls_db[self.addr][1][endpoint] = cost
        if endpoint not in self.ls_db:
            self.ls_db[endpoint] = [0, {self.addr: cost}]
        self.seq_num += 1
        self.logger.info(f"Tang so thu tu len {self.seq_num}")
        self._broadcast_link_state()
        self._compute_forwarding_table()

    def handle_remove_link(self, port):
        # Xu ly xoa lien ket tai cong port
        if port in self.neighbors:
            neighbor = self.neighbors[port]
            self.logger.info(f"Xoa lien ket: cong {port} den {neighbor}")
            del self.neighbors[port]
            if neighbor in self.neighbor_costs:
                del self.neighbor_costs[neighbor]
            if neighbor in self.ls_db[self.addr][1]:
                del self.ls_db[self.addr][1][neighbor]
            if neighbor in self.ls_db:
                del self.ls_db[neighbor][1][self.addr]
                if not self.ls_db[neighbor][1]:
                    del self.ls_db[neighbor]
            self.seq_num += 1
            self.logger.info(f"Tang so thu tu len {self.seq_num}")
            self._broadcast_link_state()
            self._compute_forwarding_table()
        else:
            self.logger.info(f"Thu xoa lien ket khong ton tai tren cong {port}")

    def handle_time(self, time_ms):
        # Xu ly thoi gian de gui trang thai lien ket dinh ky
        if time_ms - self.last_time >= self.heartbeat_time:
            self.last_time = time_ms
            self.logger.info(f"Kich hoat heartbeat tai thoi diem {time_ms} ms")
            self._broadcast_link_state()

    def _broadcast_link_state(self):
        # Phat tan trang thai lien ket den tat ca hang xom
        lsp = {
            'seq_num': self.seq_num,
            'links': self.ls_db[self.addr][1]
        }
        packet = Packet(
            kind=Packet.ROUTING,
            src_addr=self.addr,
            dst_addr=None,
            content=json.dumps(lsp)
        )
        self.logger.info(f"Phat tan goi tin trang thai lien ket voi so thu tu {self.seq_num}, lien ket: {lsp['links']}")
        for port in self.neighbors:
            self.logger.info(f"Gui goi tin trang thai lien ket den cong {port} (hang xom: {self.neighbors[port]})")
            self.send(port, packet)

    def _compute_forwarding_table(self):
        # Tinh toan bang chuyen tiep bang thuat toan Dijkstra
        self.logger.info(f"Tinh toan bang chuyen tiep voi ls_db: {self.ls_db}, hang xom: {self.neighbors}")
        all_nodes = set(self.ls_db.keys())
        distances = {node: float('inf') for node in all_nodes}
        distances[self.addr] = 0
        predecessors = {node: None for node in all_nodes}
        pq = [(0, self.addr)]
        visited = set()

        while pq:
            current_dist, novel = heapq.heappop(pq)
            if novel in visited:
                continue
            visited.add(novel)
            if novel in self.ls_db:
                for neighbor, cost in self.ls_db[novel][1].items():
                    if neighbor not in all_nodes:
                        all_nodes.add(neighbor)
                        distances[neighbor] = float('inf')
                        predecessors[neighbor] = None
                    distance = current_dist + cost
                    if distance < distances[neighbor]:
                        distances[neighbor] = distance
                        predecessors[neighbor] = novel
                        heapq.heappush(pq, (distance, neighbor))
                        self.logger.debug(f"Cap nhat khoang cach den {neighbor}: {distance} qua {novel}")

        self.forwarding_table = {}
        for dest in all_nodes:
            if dest == self.addr or distances[dest] == float('inf'):
                continue
            path = []
            novel = dest
            while novel is not None:
                path.append(novel)
                novel = predecessors[novel]
            if self.addr not in path:
                continue
            path = path[::-1]
            if len(path) < 2:
                continue
            next_hop = path[1]
            self.forwarding_table[dest] = (next_hop, distances[dest])
            self.logger.info(f"Them tuyen den {dest} qua buoc nhay tiep theo {next_hop} voi chi phi {distances[dest]} (duong di: {path})")

        self.logger.info(f"Cap nhat bang chuyen tiep: {self.forwarding_table}")

    def __repr__(self):
        # Tra ve chuoi bieu dien trang thai router de debug
        return (f"LSrouter(dia chi={self.addr}, "
                f"hang xom={self.neighbors}, "
                f"bang chuyen={self.forwarding_table})")