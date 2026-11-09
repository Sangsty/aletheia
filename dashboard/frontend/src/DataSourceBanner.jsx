export default function DataSourceBanner({ dataSource }) {
  if (!dataSource) return null;
  const isReal = dataSource.startsWith("postgres");
  return (
    <div className={`data-source-banner ${isReal ? "real" : "sample"}`}>
      {isReal ? "Live data" : "Sample data"}: {dataSource}
    </div>
  );
}
