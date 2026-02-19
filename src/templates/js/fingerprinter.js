// Collect fingerprint details
function collectFingerprint() {
	return {
		userAgent: navigator.userAgent,
	};
}

function createFingerprintHash(fingerprint) {
	const hash = btoa(JSON.stringify(fingerprint)).slice(0, 32);
	console.log("[Fingerprinter] Generated fingerprint:", hash);
	return hash;
}

// Exported async function for main HTML to call
export async function runFingerprinting() {
	console.log("[Fingerprinter] Starting...");

	if (document.readyState === "loading") {
		await new Promise((resolve) => {
			document.addEventListener("DOMContentLoaded", resolve);
		});
	}

	const fingerprint = collectFingerprint();
	const hash = createFingerprintHash(fingerprint);

	console.log("[Fingerprinter] Completed.");
	return hash;
}
