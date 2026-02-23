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
 * uefitool.cpp
 */

#include "uefitool.h"
#include "UEFITool/common/nvram.h"
#include "UEFITool/common/types.h"
#include "guids.h"
#include <codecvt>
#include <cstddef>
#include <iostream>
#include <locale>
#include <memory>
#include <string>
#include <vector>

void efiloader::Uefitool::get_unique_name(std::string &name) {
  // If the given name is already in use, create a new one
  std::string new_name = name;
  std::string suf;
  int index = 0;
  while (!(unique_names.insert(new_name).second)) {
    suf = "_" + std::to_string(++index);
    new_name = name + static_cast<std::string>(suf.c_str());
  }
  name = new_name;
}

void efiloader::Uefitool::get_image_guid(std::string &image_guid,
                                         UModelIndex index) {
  UString guid;
  UModelIndex guid_index;
  switch (model.subtype(model.parent(index))) {
  case EFI_SECTION_GUID_DEFINED:
    if (model.type(model.parent(index)) == Types::File) {
      guid_index = model.parent(index);
    } else {
      guid_index = model.parent(model.parent(index));
    }
    if (model.subtype(guid_index) == EFI_SECTION_COMPRESSION)
      guid_index = model.parent(guid_index);
    break;
  case EFI_SECTION_COMPRESSION:
    guid_index = model.parent(model.parent(index));
    break;
  default:
    guid_index = model.parent(index);
  }
  // get parent header and read GUID
  guid = guidToUString(
      readUnaligned((const EFI_GUID *)(model.header(guid_index).constData())));
  image_guid = reinterpret_cast<char *>(guid.data);
}

std::string efiloader::Uefitool::lookup_name(std::string &image_guid) {
  auto it = g_module_guids.find(image_guid);
  if (it != g_module_guids.end()) {
    return it->second;
  }
  return image_guid;
}

void efiloader::Uefitool::dump(const UModelIndex &index,
                               std::shared_ptr<efiloader::File> file) {
  std::string module_name("");
  std::string section_guid("");
  UString guid;

  switch (model.subtype(index)) {
  case EFI_SECTION_PE32:
    if (unique_indexes.find(index) == unique_indexes.end()) {
      unique_indexes.insert(index);
      file->is_pe = true;
      file->ubytes = model.body(index);
    }
    break;
  case EFI_SECTION_TE:
    if (unique_indexes.find(index) == unique_indexes.end()) {
      unique_indexes.insert(index);
      file->is_te = true;
      file->ubytes = model.body(index);
    }
    break;
  case EFI_SECTION_RAW:
    if (unique_indexes.find(index) == unique_indexes.end()) {
      unique_indexes.insert(index);
      if (file->is_pe || file->is_te) {
        // this file is already processed as PE/TE
        // but we are only interested in individual
        // RAW sections (which are not part of PE/TE modules)
        break;
      }
      if (is_file_index(model.parent(index))) {
        file->is_raw = true;
        file->ubytes = model.body(index);
      }
    }
    break;
  case EFI_SECTION_DXE_DEPEX:
    file->depex = model.body(index);
    break;
  case EFI_SECTION_PEI_DEPEX:
    file->depex = model.body(index);
    break;
  case EFI_SECTION_MM_DEPEX:
    file->depex = model.body(index);
    break;
  case EFI_SECTION_USER_INTERFACE:
    if (unique_indexes.find(index) == unique_indexes.end()) {
      unique_indexes.insert(index);
      file->has_ui = true;
      if (!file->is_ok) {
        UByteArray uname = model.body(index);
        std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t>
            convert;
        module_name = convert.to_bytes(
            reinterpret_cast<const char16_t *>(uname.constData()));

        get_image_guid(file->guid, index);
        if (!unique_guids.insert(file->guid).second) {
          file->is_duplicate = true;
        }

        if (!module_name.size()) {
          // lookup by file GUID
          module_name = lookup_name(file->guid);
        }

        file->real_name = module_name;

        get_unique_name(module_name);
        file->name = module_name;

        if (file->is_pe || file->is_te) {
          file->is_ok = true;
          files.push_back(file);
        }
      }
    }
    break;
  case EFI_SECTION_GUID_DEFINED:
    get_image_guid(section_guid, index);
    if (unique_section_guids.find(section_guid) == unique_section_guids.end()) {
      unique_section_guids.insert(section_guid);
      guid_defined_sections.push_back(Section(section_guid));
    }
    for (int i = 0; i < model.rowCount(index); i++) {
      dump(index.child(i, 0), file);
    }
    break;
  case EFI_SECTION_COMPRESSION:
    for (int i = 0; i < model.rowCount(index); i++) {
      dump(index.child(i, 0), file);
    }
    break;
  default:
    break;
  }

  dump(index);
}

void efiloader::Uefitool::dump(const UModelIndex &index) {
  USTATUS err;
  if (is_file_index(index)) {
    std::shared_ptr<efiloader::File> file =
        std::make_shared<File>(model.subtype(index));

    for (int i = 0; i < model.rowCount(index); i++) {
      dump(index.child(i, 0), file);
    }

    if ((file->is_pe || file->is_te) && !file->is_ok) {
      file->is_ok = true;
      if (!file->has_ui) {
        get_image_guid(file->guid, index.child(0, 0));
        if (!unique_guids.insert(file->guid).second) {
          file->is_duplicate = true;
        }
        file->name = lookup_name(file->guid);
        file->real_name = file->name;
        get_unique_name(file->name);
      }
      files.push_back(file);
    }

    else if (file->is_raw && !file->is_ok) {
      if (!file->has_ui) {
        get_image_guid(file->guid, index.child(0, 0));
        if (!unique_guids.insert(file->guid).second) {
          file->is_duplicate = true;
        }
        file->name = lookup_name(file->guid);
        file->real_name = file->name;
        get_unique_name(file->name);
      }
      files.push_back(file);
    }
  } else if (model.type(index) == Types::VssEntry) {
    auto guid = model.name(index);
    auto name = model.text(index);
    auto subtype = model.subtype(index);
    auto attrs =
        ((VSS_VARIABLE_HEADER *)model.header(index).data())->Attributes;
    auto body = model.body(index);

    if (guid != "Invalid") {
      auto var = Var(VAR_TYPE::VSS, subtype, attrs,
                     std::string((const char *)guid, guid.length()),
                     std::string((const char *)name, name.length()), body);

      var.state = ((VSS_VARIABLE_HEADER *)model.header(index).data())->State;

      vars.push_back(var);
    }

    for (int i = 0; i < model.rowCount(index); i++) {
      dump(index.child(i, 0));
    }
  } else if (model.type(index) == Types::NvarEntry) {
    auto guid = model.name(index);
    auto name = model.text(index);
    auto subtype = model.subtype(index);
    auto attrs = ((NVAR_ENTRY_HEADER *)model.header(index).data())->Attributes;
    auto body = model.body(index);

    if (guid != "Invalid") {
      auto var = Var(VAR_TYPE::NVAR, subtype, attrs,
                     std::string((const char *)guid, guid.length()),
                     std::string((const char *)name, name.length()), body);

      if (attrs & NVRAM_NVAR_ENTRY_EXT_HEADER && !model.hasEmptyTail(index)) {
        auto tail = model.tail(index);
        var.ext_attrs = tail[0];
      }

      vars.push_back(var);
    }

    for (int i = 0; i < model.rowCount(index); i++) {
      dump(index.child(i, 0));
    }
  } else if (model.type(index) == Types::EvsaEntry) {
    auto guid = model.name(index);
    auto name = model.text(index);
    auto subtype = model.subtype(index);

    if (subtype != Subtypes::GuidEvsaEntry &&
        subtype != Subtypes::NameEvsaEntry &&
        guid != "Invalid") {
      auto attrs =
        (subtype == Subtypes::DataEvsaEntry)
        ? ((EVSA_DATA_ENTRY *)model.header(index).data())->Attributes
        : 0;

      auto body = model.body(index);

      auto var = Var(VAR_TYPE::EVSA, subtype, attrs,
                     std::string((const char *)guid, guid.length()),
                     std::string((const char *)name, name.length()), body);

      vars.push_back(var);
    }

    for (int i = 0; i < model.rowCount(index); i++) {
      dump(index.child(i, 0));
    }
  } else if (model.type(index) == Types::Microcode &&
             model.subtype(index) == Subtypes::IntelMicrocode) {
    UByteArray microcode = model.body(index);
    const INTEL_MICROCODE_HEADER *ucodeHeader =
        (const INTEL_MICROCODE_HEADER *)microcode.constData();
    UString date = usprintf("%02X.%02X.%04x", ucodeHeader->DateDay,
                            ucodeHeader->DateMonth, ucodeHeader->DateYear);
    UINT32 cpu_signature = ucodeHeader->ProcessorSignature;
    UINT32 update_revision = ucodeHeader->UpdateRevision;
    UINT8 processor_flags = ucodeHeader->ProcessorFlags;
    microcodes.push_back(Microcode(reinterpret_cast<char *>(date.data),
                                   cpu_signature, update_revision,
                                   processor_flags, MICROCODE_VENDOR::INTEL));
  } else if (model.type(index) == Types::Microcode &&
             model.subtype(index) == Subtypes::AmdMicrocode) {
    UByteArray microcode = model.body(index);
    const AMD_MICROCODE_HEADER *ucodeHeader =
        (const AMD_MICROCODE_HEADER *)microcode.constData();
    UString date = usprintf("%02X.%02X.%04x", getDayMicrocodeAmd(ucodeHeader),
                            getMonthMicrocodeAmd(ucodeHeader),
                            getYearMicrocodeAmd(ucodeHeader));
    UINT32 cpu_signature = getCpuIdMicrocodeAmd(ucodeHeader);
    UINT32 update_revision = ucodeHeader->UpdateRevision;
    UINT8 processor_flags = 0;
    microcodes.push_back(Microcode(reinterpret_cast<char *>(date.data),
                                   cpu_signature, update_revision,
                                   processor_flags, MICROCODE_VENDOR::AMD));
  } else {
    for (int i = 0; i < model.rowCount(index); i++) {
      dump(index.child(i, 0));
    }
  }
}

void efiloader::Uefitool::dump() { return dump(model.index(0, 0)); }

std::unique_ptr<efiloader::Uefitool>
efiloader::uefitool_new(const unsigned char *buffer, size_t buffer_size) {
  return std::make_unique<efiloader::Uefitool>(
      reinterpret_cast<const char *>(buffer), buffer_size);
}

void efiloader::uefitool_dump(std::unique_ptr<Uefitool> &uefitool) {
  uefitool->dump();
}

void efiloader::uefitool_for_each_module(
    const std::unique_ptr<Uefitool> &uefitool, char *callback,
    char *user_data) {
  for (auto &f : uefitool->files) {
    if (f->is_ok) {
      if (CONTINUE_OR_STOP::STOP ==
          f->callback(reinterpret_cast<ModuleCallback>(callback),
                      reinterpret_cast<ModuleUserData>(user_data))) {
        break;
      }
    }
  }
}

size_t
efiloader::uefitool_count_modules(const std::unique_ptr<Uefitool> &uefitool) {
  size_t count = 0;
  for (auto &f : uefitool->files) {
    if (f->is_ok) {
      count++;
    }
  }
  return count;
}

void efiloader::uefitool_for_each_raw_section(
    const std::unique_ptr<Uefitool> &uefitool, char *callback,
    char *user_data) {
  for (auto &f : uefitool->files) {
    if (f->is_raw && !f->is_ok) {
      if (CONTINUE_OR_STOP::STOP ==
          f->callback(reinterpret_cast<ModuleCallback>(callback),
                      reinterpret_cast<ModuleUserData>(user_data))) {
        break;
      }
    }
  }
}

size_t efiloader::uefitool_count_raw_sections(
    const std::unique_ptr<Uefitool> &uefitool) {
  size_t count = 0;
  for (auto &f : uefitool->files) {
    if (f->is_raw && !f->is_ok) {
      count++;
    }
  }
  return count;
}

void efiloader::uefitool_for_each_nvram(
    const std::unique_ptr<Uefitool> &uefitool, char *callback,
    char *user_data) {
  for (auto &v : uefitool->vars) {
    if (CONTINUE_OR_STOP::STOP ==
        v.callback(reinterpret_cast<VarCallback>(callback),
                   reinterpret_cast<VarUserData>(user_data))) {
      break;
    }
  }
}

size_t
efiloader::uefitool_count_nvram(const std::unique_ptr<Uefitool> &uefitool) {
  return std::size(uefitool->vars);
}

void efiloader::uefitool_for_each_microcode(
    const std::unique_ptr<Uefitool> &uefitool, char *callback,
    char *user_data) {
  for (auto &m : uefitool->microcodes) {
    if (CONTINUE_OR_STOP::STOP ==
        m.callback(reinterpret_cast<MicrocodeCallback>(callback),
                   reinterpret_cast<MicrocodeUserData>(user_data))) {
      break;
    }
  }
}

size_t
efiloader::uefitool_count_microcode(const std::unique_ptr<Uefitool> &uefitool) {
  return std::size(uefitool->microcodes);
}

void efiloader::uefitool_for_each_guid_defined_section(
    const std::unique_ptr<Uefitool> &uefitool, char *callback,
    char *user_data) {
  for (auto &s : uefitool->guid_defined_sections) {
    if (CONTINUE_OR_STOP::STOP ==
        s.callback(reinterpret_cast<SectionCallback>(callback),
                   reinterpret_cast<SectionUserData>(user_data))) {
      break;
    }
  }
}

size_t efiloader::uefitool_count_guid_defined_sections(
    const std::unique_ptr<Uefitool> &uefitool) {
  return std::size(uefitool->guid_defined_sections);
}
