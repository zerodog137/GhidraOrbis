package orbis.loader;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.elf.ElfException;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import orbis.self.EncryptedSelfException;
import orbis.self.SelfHeader;

public class GhidraOrbisSelfLoader extends GhidraOrbisElfLoader {

	@Override
	public String getName() {
		return "Orbis SELF";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		if (!SelfHeader.isSelf(provider)) {
			return Collections.emptyList();
		}
		try {
			SelfHeader header = new SelfHeader(provider);
			return findSupportedLoadSpecs(header.buildElfHeader());
		} catch (ElfException e) {
			// do nothing
			Msg.error(this, e);
		} catch (EncryptedSelfException e) {
			Msg.showInfo(this, null, "Encrypted SELF detected", "Encrypted SELF files cannot be loaded");
		}
		return Collections.emptyList();
	}

	@Override
	public void load(Program program, ImporterSettings settings)
			throws IOException, CancelledException {
		try {
			SelfHeader header = new SelfHeader(settings.provider());
			ByteProvider elfByteProvider = header.getElfByteProvider();
			ImporterSettings newSettings = new ImporterSettings(elfByteProvider,
				program.getName(), settings.project(), settings.projectRootPath(),
				settings.mirrorFsLayout(), settings.loadSpec(), settings.options(),
				settings.consumer(), settings.log(), settings.monitor());
			super.load(program, newSettings);
			elfByteProvider.close();
		} catch (EncryptedSelfException e) {
			Msg.showInfo(this, null, "Import Failed", "SELF is encrypted and cannot be loaded");
			throw new CancelledException();
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram, boolean mirrorFsLayout) {
		try {
			SelfHeader header = new SelfHeader(provider);
			ByteProvider elfByteProvider = header.getElfHeaderByteProvider();
			return super.getDefaultOptions(
				elfByteProvider, loadSpec, domainObject, loadIntoProgram, mirrorFsLayout);
		} catch (Exception e) {
			// already logged
			return Collections.emptyList();
		}
	}
}
