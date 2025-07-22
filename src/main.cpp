#include <ftxui/dom/elements.hpp>
#include <ftxui/screen/screen.hpp>
#include <ftxui/component/component.hpp>
#include <ftxui/component/event.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/screen/color.hpp>
#include <fstream>
#include <vector>
#include <iomanip>
#include <sstream>
#include <cctype>
#include <iostream>
#include <optional>

using namespace ftxui;

struct HexEditorState {
    std::string filename;
    std::vector<char> data;
    std::string status;

    size_t cursor_line = 0;
    int cursor_col = 0;
    bool edit_mode = false;
    std::string edit_buffer;

    // Display settings
    const size_t visible_lines = 20;
    const size_t scroll_offset = 5;

    // Search settings
    bool search_window_open = false;
    std::string search_query;
    size_t search_cursor = 0;
    std::vector<size_t> search_results;
    size_t current_search_result = 0;

    struct PartitionInfo {
        size_t start;
        size_t end;
    };
    
    // Executable Partitions
    std::optional<PartitionInfo> mz_partition;
    std::optional<PartitionInfo> dos_stub_partition;
    std::optional<PartitionInfo> pe_partition;
    std::optional<PartitionInfo> elf_partition;
    std::optional<PartitionInfo> mach_o_partition;

    // PNG Partition
    std::optional<PartitionInfo> signuature_partition;
    std::optional<PartitionInfo> length_chunk_partition;
    std::optional<PartitionInfo> type_chunk_partition;
    std::optional<PartitionInfo> data_chunk_partition;
    std::optional<PartitionInfo> crc_chunk_partition;
};

enum Platform {
    Windows, Linux, MacOS, Unknown
};

Platform CheckPlatforms(const HexEditorState& state) {
    const unsigned char* header = reinterpret_cast<const unsigned char*>(state.data.data());
    // MZ Mode
    if (header[0] == 0x4d && // M
        header[1] == 0x5a) { // Z
        return Platform::Windows;
    }
    // ELF Mode
    if (header[0] == 0x7f &&
        header[1] == 0x45 && // E
        header[2] == 0x4c && // L
        header[3] == 0x46) { // F
        return Platform::Linux;
    }
    // Mach-O Mode
    if ((header[0] == 0xca && header[1] == 0xfe  &&
         header[2] == 0xba && header[3] == 0xbe) ||  // Fat Binary
        (header[0] == 0xfe && header[1] == 0xed  &&
         header[2] == 0xfa && header[3] == 0xce) ||  // 32-bit Mach-O
        (header[0] == 0xfe && header[1] == 0xed  &&
         header[2] == 0xfa && header[3] == 0xcf) ) { // 64-bit Mach-O
        return Platform::MacOS;
    }
    return Platform::Unknown;
}

void DetermineExecutablePartitions(HexEditorState& state) {
    size_t file_size = state.data.size();
    Platform plat = CheckPlatforms(state);
    // MZ Check
    if (plat == Windows) {
        state.mz_partition = HexEditorState::PartitionInfo{0, 0x3f};
        if (file_size >= 0x40) {
            state.dos_stub_partition = HexEditorState::PartitionInfo{0x40, 0};
            if (file_size >= 0x3c + 4) {
                uint32_t e_lfanew = *(reinterpret_cast<const uint32_t*>(&state.data[0x3c]));
                state.dos_stub_partition->end = e_lfanew - 1;
                state.pe_partition = HexEditorState::PartitionInfo{e_lfanew, file_size - 1};
            }
        }
    }
    // ELF Check
    if (plat == Linux) {
        state.elf_partition = HexEditorState::PartitionInfo{0, file_size - 1};
    }
    // Mach-O Check
    if (plat == MacOS) {
        state.mach_o_partition = HexEditorState::PartitionInfo{0, file_size - 1};
    }
    // PNG Check
    const unsigned char png_header[] = { 0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a };
    bool is_png = true;
    for (size_t i = 0; i < sizeof(png_header); i++) {
        if (static_cast<unsigned char>(state.data[i]) != png_header[i]) {
            is_png = false;
            break;
        }
    }
    if (is_png) {
        state.signuature_partition = HexEditorState::PartitionInfo{0, sizeof(png_header) - 1};
        size_t length_chunk_start = sizeof(png_header);
        if (file_size >= length_chunk_start + 4) {
            state.length_chunk_partition = HexEditorState::PartitionInfo{length_chunk_start, length_chunk_start + 3};
            size_t type_chunk_start = length_chunk_start + 4;
            if (file_size >= type_chunk_start + 4) {
                state.type_chunk_partition = HexEditorState::PartitionInfo{type_chunk_start, type_chunk_start + 3};
                size_t data_chunk_start = type_chunk_start + 4;
                if (file_size >= data_chunk_start + 4) {
                    state.data_chunk_partition = HexEditorState::PartitionInfo{data_chunk_start, file_size - 8 - 1};
                    state.crc_chunk_partition = HexEditorState::PartitionInfo{file_size - 8, file_size - 1};
                }
            }
        }
    }
 }

void LoadFile(HexEditorState& state, bool nerd) {
    std::ifstream file(state.filename, std::ios::binary);
    if (!file) {
        state.status = "Failed(Opening " + state.filename +")";
        return;
    }

    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);

    state.data.resize(size);
    file.read(state.data.data(), size);
    file.close();

    state.status = "Loaded: ";

    Platform plat = CheckPlatforms(state);

    if (nerd) {
        switch (plat) {
        case Windows:
            state.status += "  ";
            break;
        case Linux:
            state.status += "  ";
            break;
        case MacOS:
            state.status += "  ";
            break;
        case Unknown:
            state.status += "  ";
            break;
        default:
            break;
        }
    }
    state.status += state.filename + " (" + std::to_string(size) + " bytes)";
}

void SaveFile(HexEditorState& state) {
    std::ofstream file(state.filename, std::ios::binary);
    if (!file) {
        state.status = "Error saving file!";
        return;
    }

    file.write(state.data.data(), state.data.size());
    file.close();
    state.status = "Saved: " + state.filename;
}

void SearchHex(HexEditorState& state, const std::string& query) {
    state.search_results.clear();
    if (query.empty()) return;

    std::vector<unsigned char> query_bytes;
    for (size_t i = 0; i < query.size(); i += 2) {
        if (i + 1 < query.size()) {
            std::string byte_str = query.substr(i, 2);
            try {
                unsigned int byte = std::stoul(byte_str, nullptr, 16);
                query_bytes.push_back(static_cast<unsigned char>(byte));
            } catch (...) {}
        }
    }

    for (size_t i = 0; i <= state.data.size() - query_bytes.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < query_bytes.size(); ++j) {
            if (static_cast<unsigned char>(state.data[i + j]) != query_bytes[j]) {
                match = false;
                break;
            }
        }
        if (match) {
            state.search_results.push_back(i);
        }
    }

    state.current_search_result = 0;
    if (!state.search_results.empty()) {
        size_t pos = state.search_results[state.current_search_result];
        state.cursor_line = pos / 16;
        state.cursor_col = pos % 16;
    }
}

void SearchAscii(HexEditorState& state, const std::string& query) {
    state.search_results.clear();
    if (query.empty()) return;

    for (size_t i = 0; i <= state.data.size() - query.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < query.size(); ++j) {
            if (state.data[i + j] != query[j]) {
                match = false;
                break;
            }
        }
        if (match) {
            state.search_results.push_back(i);
        }
    }

    state.current_search_result = 0;
    if (!state.search_results.empty()) {
        size_t pos = state.search_results[state.current_search_result];
        state.cursor_line = pos / 16;
        state.cursor_col = pos % 16;
    }
}

void Search(HexEditorState& state) {
    std::string query = state.search_query;
    if (query.substr(0, 2) == "0x" || query.substr(0, 2) == "0X") {
        query = query.substr(2);
        SearchHex(state, query);
    } else {
        SearchAscii(state, query);
    }
}

Element RenderHexEditor(HexEditorState& state) {
    std::vector<Element> lines;
    int bytes_per_line = 16;
    size_t offset = 0;

    const Color COLOR_MZ_HEADER = Color::Blue;
    const Color COLOR_DOS_STUB = Color::Cyan;
    const Color COLOR_PE_PARTITION = Color::Green;
    const Color COLOR_ELF_HEADER = Color::Blue;
    const Color COLOR_ELF_PARTITION = Color::Green;
    const Color COLOR_MACHO_HEADER = Color::Blue;
    const Color COLOR_MACHO_PARTITION = Color::Green;
    const Color COLOR_PNG_SIGNATURE = Color::Blue;
    const Color COLOR_PNG_IHDR_CHUNK = Color::Cyan;
    const Color COLOR_PNG_IDAT_CHUNK = Color::Green;
    const Color COLOR_PNG_IEND_CHUNK = Color::Magenta;  
    const Color COLOR_SEARCH_RESULT = Color::Yellow; 
    const Color COLOR_CURSOR = Color::Red;

    // Header
    lines.push_back(
        hbox({
            text("Offset  ") | bold,
            text("00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F") | bold,
            text("  ASCII") | bold
        })
    );

    // Calculate total lines
    size_t total_lines = (state.data.size() + bytes_per_line - 1) / bytes_per_line;

    // Determine visible range
    size_t start_line = (state.cursor_line > state.scroll_offset) ?
                        (state.cursor_line - state.scroll_offset) : 0;
    start_line = (start_line < total_lines) ? start_line : 0;
    size_t end_line = std::min(start_line + state.visible_lines, total_lines);

    // Data lines
    for (size_t line = start_line; line < end_line; ++line) {
        offset = line * bytes_per_line;
        std::vector<Element> hex_elements;
        std::vector<Element> ascii_elements;
        std::stringstream ss;

        ss << std::setw(6) << std::setfill('0') << std::hex << offset;
        // Offset column
        hex_elements.push_back(text(ss.str()) | color(Color::Magenta));
        hex_elements.push_back(text("  "));

        // Hex data
        for (int i = 0; i < bytes_per_line; ++i) {
            size_t pos = offset + i;
            if (pos < state.data.size()) {
                unsigned char byte = static_cast<unsigned char>(state.data[pos]);
                std::string byte_str = std::format("{:02X}", byte);
                Element byte_element = text(byte_str);

                // 检查分区并应用颜色
                bool is_in_partition = false;
                Color partition_color;

                // MZ/PE格式分区检查
                if (state.mz_partition && pos >= state.mz_partition->start && pos <= state.mz_partition->end) {
                    partition_color = COLOR_MZ_HEADER;
                    is_in_partition = true;
                } else if (state.dos_stub_partition && pos >= state.dos_stub_partition->start && pos <= state.dos_stub_partition->end) {
                    partition_color = COLOR_DOS_STUB;
                    is_in_partition = true;
                } else if (state.pe_partition && pos >= state.pe_partition->start && pos <= state.pe_partition->end) {
                    partition_color = COLOR_PE_PARTITION;
                    is_in_partition = true;
                } else if (state.elf_partition && pos >= state.elf_partition->start && pos <= state.elf_partition->end) {
                    partition_color = (pos <= 0x3F) ? COLOR_ELF_HEADER : COLOR_ELF_PARTITION;
                    is_in_partition = true;
                } else if (state.mach_o_partition && pos >= state.mach_o_partition->start && pos <= state.mach_o_partition->end) {
                    partition_color = (pos <= 0x3F) ? COLOR_MACHO_HEADER : COLOR_MACHO_PARTITION;
                    is_in_partition = true;
                } else if (state.signuature_partition && pos >= state.signuature_partition->start && pos <= state.signuature_partition->end) {
                    partition_color = COLOR_PNG_SIGNATURE;
                    is_in_partition = true;
                } else if (state.length_chunk_partition && pos >= state.length_chunk_partition->start && pos <= state.length_chunk_partition->end) {
                    partition_color = COLOR_PNG_IHDR_CHUNK;
                    is_in_partition = true;
                } else if (state.type_chunk_partition && pos >= state.type_chunk_partition->start && pos <= state.type_chunk_partition->end) {
                    partition_color = COLOR_PNG_IHDR_CHUNK;
                    is_in_partition = true;
                } else if (state.data_chunk_partition && pos >= state.data_chunk_partition->start && pos <= state.data_chunk_partition->end) {
                    partition_color = COLOR_PNG_IDAT_CHUNK;
                    is_in_partition = true;
                } else if (state.crc_chunk_partition && pos >= state.crc_chunk_partition->start && pos <= state.crc_chunk_partition->end) {
                    partition_color = COLOR_PNG_IEND_CHUNK;
                    is_in_partition = true;
                }
                // Apply partition color if in partition
                if (is_in_partition) {
                    byte_element = byte_element | color(partition_color);
                }

                // Highlight search results
                bool is_search_result = false;
                for (size_t result : state.search_results) {
                    if (pos >= result && pos < result + state.search_query.size() / 2) {
                        is_search_result = true;
                        break;
                    }
                }

                // Highlight active byte
                if (line == state.cursor_line && i == state.cursor_col) {
                    if (state.edit_mode) {
                        byte_element = byte_element | color(COLOR_CURSOR);
                    } else {
                        byte_element = byte_element | bgcolor(Color::GrayDark);
                    }
                } else if (is_search_result) {
                    byte_element = byte_element | bgcolor(COLOR_SEARCH_RESULT);
                }

                hex_elements.push_back(byte_element);
                hex_elements.push_back(text(" "));

                // ASCII representation
                char c = state.data[pos];
                Element ascii_char = text(std::string(1, std::isprint(c) ? c : '.'));
                if (is_in_partition) {
                    ascii_char = ascii_char | color(partition_color);
                }
                if (line == state.cursor_line && i == state.cursor_col) {
                    ascii_char = ascii_char | bgcolor(Color::GrayDark);
                } else if (is_search_result) {
                    ascii_char = ascii_char | bgcolor(COLOR_SEARCH_RESULT);
                }
                ascii_elements.push_back(ascii_char);
            } else {
                hex_elements.push_back(text("   "));
                ascii_elements.push_back(text(" "));
            }
        }

        // Create line element
        auto hex_text = hbox(std::move(hex_elements));
        auto ascii_text = hbox(std::move(ascii_elements));

        lines.push_back(hbox({hex_text, text("  "), ascii_text}));
    }

    // Status bar
    lines.push_back(
        hbox({
            text(state.status) | flex,
            text(" | "),
            text("Enter: Edit"),
            text(" | "),
            text("Ctrl+Q: Quit"),
            text(" | "),
            text("Esc: Cancel"),
            text(" | "),
            text("Ctrl+F: Search"),
        }) | border
    );

    return window(
        text("Hex Editor") | hcenter | bold,
        vbox(std::move(lines)) | flex | border
    );
}

Element RenderSearchWindow(HexEditorState& state) {
    
    std::string search_display = state.search_query;
    search_display.insert(state.search_cursor, "|");
    
    return window(
        text("Search") | hcenter | bold,
        vbox({
            hbox({
                text("Search Query: "),
                text(search_display)
            })
        }) | border
    );
}

const char* options[] = {
    "--light",
    "--nerd"
};
const int options_num = 2;

// Option Check
bool is_light = false;
bool is_nerd   = false;

int file_index = 1;

int main(int argc, char* argv[]) {
    if (argc < 2 || (argc == 2 && std::string(argv[1]) == std::string("--help"))) {
        std::cout << "Usage: " << argv[0] << " [-OPTIONS] <filename>\n";
        std::cout << "-OPTIONS:" << std::endl;
        std::cout << "  --light: open highlight support" << std::endl;
        std::cout << "  --nerd : open Need Fonts support" << std::endl;
        return 1;
    }
    HexEditorState state;
    while (file_index < argc) {
        bool is_option = false;
        for (int i = 0; i < options_num; ++i) {
            if (std::string(argv[file_index]) == options[i]) {
                is_option = true;
                switch (i) {

                    // Highlight Support
                case 0:
                    is_light = true;
                    break;

                    // Nerd Font Support
                case 1:
                    is_nerd   = true;
                default:
                    break;
                }
                break;
            }
        }

        if (!is_option) {
            break;
        }
        
        ++file_index;
    }

    if (file_index >= argc) {
        std::cout << "Usage: " << argv[0] << "[-OPTIONS] <filename>\n";
        std::cout << "-OPTIONS:" << std::endl;
        std::cout << "  --modern: open highlight support" << std::endl;
        std::cout << "  --nerd  : open Need Fonts support" << std::endl;
        return 1;
    }

    state.filename = argv[file_index];
    
    if (is_nerd) {
        LoadFile(state, true);
    } else {
        LoadFile(state, false);
    }

    if (is_light) {
        DetermineExecutablePartitions(state);
    }

    auto screen = ScreenInteractive::Fullscreen();
    auto component = Renderer([&] {
        if (state.search_window_open) {
            return RenderSearchWindow(state);
        } else {
            return RenderHexEditor(state);
        }
    });

    component |= CatchEvent([&](Event event) {
        int bytes_per_line = 16;
        size_t total_lines = (state.data.size() + bytes_per_line - 1) / bytes_per_line;
        if (state.search_window_open) {
            if (event == Event::Backspace && state.search_cursor > 0) {
                state.search_query.erase(state.search_cursor - 1, 1);
                state.search_cursor--;
                return true;
            }
            if (event == Event::Delete && state.search_cursor < state.search_query.size()) {
                state.search_query.erase(state.search_cursor, 1);
                return true;
            }
            if (event == Event::ArrowLeft && state.search_cursor > 0) {
                state.search_cursor--;
                return true;
            }
            if (event == Event::ArrowRight && state.search_cursor < state.search_query.size()) {
                state.search_cursor++;
                return true;
            }
            
            if (event.is_character()) {
                std::string input = event.character();
                if (!input.empty()) {
                    // char c = input[0];
                    state.search_query.insert(state.search_cursor, input);
                    state.search_cursor++;
                }
                return true;
            }
            
            if (event == Event::Return) {
                Search(state);
                state.search_window_open = false;
                return true;
            }
            
            // 处理Esc键
            if (event == Event::Escape) {
                state.search_window_open = false;
                state.search_query.clear();
                state.search_cursor = 0;
                state.search_results.clear();
                return true;
            }
            
            return false;
        }

        // Navigation
        if (event == Event::ArrowUp && state.cursor_line > 0) {
            state.cursor_line--;
            return true;
        }
        if (event == Event::ArrowDown && state.cursor_line < total_lines - 1) {
            state.cursor_line++;
            return true;
        }
        if (event == Event::ArrowLeft && state.cursor_col > 0) {
            state.cursor_col--;
            return true;
        }
        if (event == Event::ArrowRight && state.cursor_col < bytes_per_line - 1) {
            state.cursor_col++;
            return true;
        }

        // Enter edit mode
        if (event == Event::Return && !state.edit_mode) {
            size_t pos = state.cursor_line * bytes_per_line + state.cursor_col;
            if (pos < state.data.size()) {
                state.edit_mode = true;
                state.edit_buffer.clear();
                return true;
            }
        }

        // Edit mode input
        if (state.edit_mode && event.is_character()) {
            std::string input = event.character();
            if (!input.empty()) {
                char c = input[0];
                if (std::isxdigit(c)) {
                    state.edit_buffer += std::toupper(c);
                    if (state.edit_buffer.size() == 2) {
                        // Convert hex to byte
                        try {
                            unsigned int byte = std::stoul(state.edit_buffer, nullptr, 16);
                            size_t pos = state.cursor_line * bytes_per_line + state.cursor_col;
                            if (pos < state.data.size()) {
                                state.data[pos] = static_cast<char>(byte);
                            }
                        } catch (...) {}

                        state.edit_mode = false;
                        state.edit_buffer.clear();
                        state.cursor_col = (state.cursor_col + 1) % bytes_per_line;
                        if (state.cursor_col == 0 && state.cursor_line < total_lines - 1) {
                            state.cursor_line++;
                        }
                    }
                }
            }
            return true;
        }

        // Cancel edit
        if (state.edit_mode && event == Event::Escape) {
            state.edit_mode = false;
            state.edit_buffer.clear();
            return true;
        }

        // Save file
        if (event == Event::CtrlS) {
            SaveFile(state);
            return true;
        }

        // Quit program
        if (event == Event::CtrlQ) {
            screen.ExitLoopClosure()();
            return true;
        }

        // Enter search mode
        if (event == Event::CtrlF) {
            state.search_window_open = true;
            state.search_query.clear();
            state.search_cursor = 0;
            state.search_results.clear();
            return true;
        }

        // Next search result
        if (event == Event::PageDown && !state.search_results.empty()) {
            state.current_search_result = (state.current_search_result + 1) % state.search_results.size();
            size_t pos = state.search_results[state.current_search_result];
            state.cursor_line = pos / 16;
            state.cursor_col = pos % 16;
            return true;
        }
        // Pre search result
        if (event == Event::PageUp && !state.search_results.empty()) {
            state.current_search_result = (state.current_search_result - 1) % state.search_results.size();
            size_t pos = state.search_results[state.current_search_result];
            state.cursor_line = pos / 16;
            state.cursor_col = pos % 16;
            return true;
        }

        if (event == Event::Delete) {
            size_t pos = state.cursor_line * bytes_per_line + state.cursor_col;
            if (pos < state.data.size()) {
                state.data.erase(state.data.begin() + pos);
                total_lines = (state.data.size() + bytes_per_line - 1) / bytes_per_line;
                if (state.cursor_col == bytes_per_line - 1 && state.cursor_line > 0) {
                    state.cursor_line--;
                    state.cursor_col = bytes_per_line - 1;
                } else if (state.cursor_col > 0) {
                    state.cursor_col--;
                } else if (state.cursor_line > 0) {
                    state.cursor_line--;
                    state.cursor_col = bytes_per_line - 1;
                }
                state.status = "Byte removed at position " + std::to_string(pos);
            }
            return true;
        }

        if (event == Event::Insert) {
            size_t pos = state.cursor_line * bytes_per_line + state.cursor_col;
            if (pos < state.data.size()) {
                state.data.insert(state.data.begin() + pos, 0);
                total_lines = (state.data.size() + bytes_per_line - 1) / bytes_per_line;
                if (state.cursor_col == bytes_per_line - 1 && state.cursor_line > 0) {
                    state.cursor_line--;
                    state.cursor_col = bytes_per_line - 1;
                } else if (state.cursor_col > 0) {
                    state.cursor_col--;
                } else if (state.cursor_line > 0) {
                    state.cursor_line--;
                    state.cursor_col = bytes_per_line - 1;
                }
                state.status = "Byte inserted at position " + std::to_string(pos);
            }
            return true;
        }

        return false;
    });

    screen.Loop(component);
    return 0;
}
