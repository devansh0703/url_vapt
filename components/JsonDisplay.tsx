// components/JsonDisplay.tsx

interface JsonDisplayProps {
  data: any;
}

// A simple function to check if a string is a URL
const isUrl = (value: any): value is string => {
  if (typeof value !== 'string') return false;
  return value.startsWith('http://') || value.startsWith('https://');
};

export default function JsonDisplay({ data }: JsonDisplayProps) {
  // Render null values
  if (data === null || data === undefined) {
    return <span>null</span>;
  }

  // If the data is an array, map over it and recursively call this component for each item.
  if (Array.isArray(data)) {
    // If the array is empty, just say so.
    if (data.length === 0) {
      return <span>(Empty Array)</span>;
    }
    return (
      <ul style={{ listStyleType: 'none', paddingLeft: '20px', margin: 0 }}>
        {data.map((item, index) => (
          <li key={index}>
            <JsonDisplay data={item} />
          </li>
        ))}
      </ul>
    );
  }

  // If the data is an object, map over its key-value pairs.
  if (typeof data === 'object') {
     const entries = Object.entries(data);
     // If the object is empty
     if (entries.length === 0) {
        return <span>&#123;&#125; (Empty Object)</span>
     }
    return (
      <ul style={{ listStyleType: 'none', paddingLeft: '20px', margin: 0 }}>
        {entries.map(([key, value]) => (
          <li key={key}>
            <strong>{key}: </strong>
            <JsonDisplay data={value} />
          </li>
        ))}
      </ul>
    );
  }

  // Otherwise, it's a primitive value (string, number, boolean).
  // We render it directly, making links clickable.
  if (isUrl(data)) {
    return <a href={data} target="_blank" rel="noopener noreferrer">{data}</a>;
  }

  return <span>{String(data)}</span>;
}
