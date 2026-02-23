/*
 * efiXloader
 * Copyright (C) 2020-2023 Binarly
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * uefitool.h
 */

#ifndef EFILOADER_UEFITOOL_H
#define EFILOADER_UEFITOOL_H

#include "UEFITool/common/LZMA/LzmaCompress.h"
#include "UEFITool/common/LZMA/LzmaDecompress.h"
#include "UEFITool/common/Tiano/EfiTianoCompress.h"
#include "UEFITool/common/Tiano/EfiTianoDecompress.h"
#include "UEFITool/common/basetypes.h"
#include "UEFITool/common/ffs.h"
#include "UEFITool/common/ffsparser.h"
#include "UEFITool/common/ffsreport.h"
#include "UEFITool/common/filesystem.h"
#include "UEFITool/common/guiddatabase.h"
#include "UEFITool/common/treeitem.h"
#include "UEFITool/common/treemodel.h"
#include "UEFITool/common/ustring.h"
#include "UEFITool/version.h"

#include "UEFITool/UEFIExtract/ffsdumper.h"
#include "UEFITool/UEFIExtract/uefidump.h"

#include <cstdint>
#include <memory>
#include <set>
#include <stdexcept>

#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#endif

enum FILE_SECTION_TYPE {
  PE_DEPENDENCY_SECTION = 0,
  PE_TE_IMAGE_SECTION = 1,
  UI_SECTION = 2,
  VERSION_SECTION = 3
};

enum VAR_TYPE {
  NVAR = 0,
  VSS = 1,
  EVSA = 2,
};

enum MICROCODE_VENDOR {
  INTEL = 0,
  AMD = 1,
};

enum CONTINUE_OR_STOP {
  CONTINUE = 0,
  STOP = 1,
};

namespace efiloader {

using ModuleCallback = CONTINUE_OR_STOP (*)(char *, const char *, const char *,
                                            const char *, std::uint8_t, bool,
                                            bool, bool, bool,
                                            const unsigned char *, size_t,
                                            const unsigned char *, size_t);
using ModuleUserData = char *;

using VarCallback = CONTINUE_OR_STOP (*)(char *, std::uint8_t, std::uint8_t,
                                         std::uint32_t, std::uint8_t,
                                         std::uint8_t, const char *,
                                         const char *, const unsigned char *,
                                         size_t);
using VarUserData = char *;

using MicrocodeCallback = CONTINUE_OR_STOP (*)(char *, const char *,
                                               std::uint32_t, std::uint32_t,
                                               std::uint8_t, std::uint8_t);
using MicrocodeUserData = char *;

using SectionCallback = CONTINUE_OR_STOP (*)(char *, const char *);
using SectionUserData = char *;

class File {
public:
  File(std::uint8_t ft)
      : ft(ft), is_pe(false), is_te(false), is_ok(false), has_ui(false),
        is_duplicate(false) {}
  CONTINUE_OR_STOP callback(ModuleCallback callback, ModuleUserData user_data) {
    return callback(user_data, name.c_str(), real_name.c_str(), guid.c_str(),
                    ft, is_pe, is_te, has_ui, is_duplicate,
                    reinterpret_cast<const unsigned char *>(depex.constData()),
                    depex.size(),
                    reinterpret_cast<const unsigned char *>(ubytes.constData()),
                    ubytes.size());
  }

  UByteArray ubytes;
  UByteArray depex;
  UByteArray uname;
  std::string name;
  std::string real_name;
  std::string guid;
  std::uint8_t ft;
  bool is_pe = false;
  bool is_te = false;
  bool is_ok = false;
  bool is_raw = false;
  bool has_ui = false;
  bool is_duplicate = false;
};

class Var {
public:
  Var(VAR_TYPE ty, UINT8 subtype, UINT32 attrs, std::string guid,
      std::string name, UByteArray data)
      : ty(ty), subtype(subtype), attrs(attrs), guid(guid), name(name),
        data(data) {}
  CONTINUE_OR_STOP callback(VarCallback callback, VarUserData user_data) {
    return callback(user_data, ty, subtype, attrs, ext_attrs, state,
                    guid.c_str(), name.c_str(),
                    reinterpret_cast<const unsigned char *>(data.constData()),
                    data.size());
  }

  UINT8 ext_attrs = 0;
  UINT8 state = 0;

private:
  VAR_TYPE ty;
  UINT8 subtype;
  UINT32 attrs;
  std::string guid;
  std::string name;
  UByteArray data;
};

class Microcode {
public:
  Microcode(std::string date, UINT32 cpu_signature, UINT32 update_revision,
            UINT8 processor_flags, MICROCODE_VENDOR vendor)
      : date(date), cpu_signature(cpu_signature),
        update_revision(update_revision), processor_flags(processor_flags),
        vendor(vendor) {}
  CONTINUE_OR_STOP callback(MicrocodeCallback callback,
                            MicrocodeUserData user_data) {
    return callback(user_data, date.c_str(), cpu_signature, update_revision,
                    processor_flags, vendor);
  }

private:
  std::string date;
  UINT32 cpu_signature;
  UINT32 update_revision;
  UINT8 processor_flags;
  MICROCODE_VENDOR vendor;
};

class Section {
public:
  Section(std::string guid) : guid(guid) {}
  CONTINUE_OR_STOP callback(SectionCallback callback,
                            SectionUserData user_data) {
    return callback(user_data, guid.c_str());
  }

private:
  std::string guid;
};

class Uefitool {
public:
  Uefitool(const char *buffer, size_t buffer_size) {
    UByteArray ubuffer(buffer, buffer_size);
    FfsParser ffs(&model);
    if (ffs.parse(ubuffer)) {
      throw std::runtime_error("failed to parse firmware image");
    }
  }
  ~Uefitool() { ; }
  void dump();
  void dump(const UModelIndex &index);
  void dump(const UModelIndex &index, std::shared_ptr<File> pe_file);
  bool is_file_index(const UModelIndex &index) {
    if (model.subtype(model.parent(index)) == EFI_SECTION_GUID_DEFINED)
      return model.type(model.parent(index)) == Types::File;
    return model.type(index) == Types::File;
  };
  void get_unique_name(std::string &image_name);
  void get_image_guid(std::string &image_guid, UModelIndex index);
  std::string lookup_name(std::string &image_guid);
  TreeModel model;
  const char *buffer;
  uint32_t buffer_size;
  std::set<UModelIndex> unique_indexes;
  std::set<std::string> unique_names;
  std::set<std::string> unique_guids;
  std::set<std::string> unique_section_guids;
  std::vector<std::shared_ptr<File>> files;
  std::vector<Var> vars;
  std::vector<Microcode> microcodes;
  std::vector<Section> guid_defined_sections;
};

std::unique_ptr<efiloader::Uefitool> uefitool_new(const unsigned char *buffer,
                                                  size_t buffer_size);
void uefitool_dump(std::unique_ptr<Uefitool> &uefitool);

void uefitool_for_each_raw_section(const std::unique_ptr<Uefitool> &uefitool,
                                   char *callback, char *user_data);
size_t uefitool_count_raw_sections(const std::unique_ptr<Uefitool> &uefitool);

void uefitool_for_each_module(const std::unique_ptr<Uefitool> &uefitool,
                              char *callback, char *user_data);
size_t uefitool_count_modules(const std::unique_ptr<Uefitool> &uefitool);

void uefitool_for_each_nvram(const std::unique_ptr<Uefitool> &uefitool,
                             char *callback, char *user_data);
size_t uefitool_count_nvram(const std::unique_ptr<Uefitool> &uefitool);

void uefitool_for_each_microcode(const std::unique_ptr<Uefitool> &uefitool,
                                 char *callback, char *user_data);
size_t uefitool_count_microcode(const std::unique_ptr<Uefitool> &uefitool);

void uefitool_for_each_guid_defined_section(
    const std::unique_ptr<Uefitool> &uefitool, char *callback, char *user_data);
size_t
uefitool_count_guid_defined_sections(const std::unique_ptr<Uefitool> &uefitool);

} // namespace efiloader

#endif // EFILOADER_UEFITOOL_H
