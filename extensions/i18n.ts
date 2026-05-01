import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";

type Params = Record<string, string | number>;
type Translate = (key: string, fallback: string, params?: Params) => string;
let translate: Translate = (_key, fallback, params) => format(fallback, params);

function format(text: string, params?: Params): string {
	if (!params) return text;
	return text.replace(/\{(\w+)\}/g, (_m, key: string) => String(params[key] ?? `{${key}}`));
}

export function t(key: string, fallback: string, params?: Params): string {
	return translate(key, fallback, params);
}

const bundles = [
	{ locale: "es", namespace: "pi-share-redacted-gist", messages: {
		"cmd.description": "Publicar una sesión de pi redactada en GitHub gist y/o un dataset de Hugging Face",
		"error.noSession": "No hay archivo de sesión persistido. Usa --session @/ruta/a/session.jsonl",
		"error.readSession": "No se pudo leer el archivo de sesión: {message}",
		"review.cancelled": "Cancelado",
		"review.applied": "La revisión aplicó {rules} regla(s) manuales de redacción; quedan {remaining} valor(es) sospechosos",
		"attestation.stopped": "La confirmación de responsabilidad no se aceptó. Detenido.",
		"error.noDataset": "No se seleccionó ningún dataset de Hugging Face.",
		"error.noPublishers": "No hay publicadores configurados. Activa gist y/o configura datasets de Hugging Face.",
		"error.multiplePublishers": "Hay varios publicadores disponibles. Usa --publisher gist|huggingface|both.",
		"select.publishTo": "Publicar en",
		"select.gist": "GitHub gist",
		"select.huggingface": "Dataset de Hugging Face",
		"select.both": "Ambos"
	}},
	{ locale: "fr", namespace: "pi-share-redacted-gist", messages: {
		"cmd.description": "Publier une session pi expurgée vers un gist GitHub et/ou un dataset Hugging Face",
		"error.noSession": "Aucun fichier de session persistant. Passez --session @/chemin/vers/session.jsonl",
		"error.readSession": "Impossible de lire le fichier de session : {message}",
		"review.cancelled": "Annulé",
		"review.applied": "La révision a appliqué {rules} règle(s) d’expurgation manuelle ; {remaining} valeur(s) suspecte(s) restante(s)",
		"attestation.stopped": "Confirmation de responsabilité non validée. Arrêt.",
		"error.noDataset": "Aucun dataset Hugging Face sélectionné.",
		"error.noPublishers": "Aucun éditeur configuré. Activez gist et/ou configurez des datasets Hugging Face.",
		"error.multiplePublishers": "Plusieurs éditeurs sont disponibles. Passez --publisher gist|huggingface|both.",
		"select.publishTo": "Publier vers",
		"select.gist": "Gist GitHub",
		"select.huggingface": "Dataset Hugging Face",
		"select.both": "Les deux"
	}},
	{ locale: "pt-BR", namespace: "pi-share-redacted-gist", messages: {
		"cmd.description": "Publicar uma sessão pi redigida em GitHub gist e/ou dataset do Hugging Face",
		"error.noSession": "Nenhum arquivo de sessão persistido. Passe --session @/caminho/para/session.jsonl",
		"error.readSession": "Falha ao ler arquivo de sessão: {message}",
		"review.cancelled": "Cancelado",
		"review.applied": "A revisão aplicou {rules} regra(s) manuais de redação; {remaining} valor(es) suspeito(s) restantes",
		"attestation.stopped": "Confirmação de responsabilidade não aceita. Interrompido.",
		"error.noDataset": "Nenhum dataset do Hugging Face selecionado.",
		"error.noPublishers": "Nenhum publicador configurado. Ative gist e/ou configure datasets do Hugging Face.",
		"error.multiplePublishers": "Há vários publicadores disponíveis. Passe --publisher gist|huggingface|both.",
		"select.publishTo": "Publicar em",
		"select.gist": "GitHub gist",
		"select.huggingface": "Dataset do Hugging Face",
		"select.both": "Ambos"
	}}
];

export function initI18n(pi: ExtensionAPI): void {
	const events = pi.events;
	if (!events) return;
	for (const bundle of bundles) events.emit("pi-core/i18n/registerBundle", bundle);
	events.emit("pi-core/i18n/requestApi", {
		namespace: "pi-share-redacted-gist",
		callback(api: { t?: Translate } | undefined) {
			if (typeof api?.t === "function") translate = api.t;
		},
	});
}
